(ns unlock-test
  (:require [babashka.http-client :as http]
            [cheshire.core :as json]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing use-fixtures]]
            [org.httpkit.server :as server]
            [unlock :as u])
  (:import (java.io BufferedReader InputStreamReader PrintWriter)
           (java.net Socket)))

;; A fake upstream that records what it receives and answers per path.

(def seen (atom []))

(defn- upstream-handler [{:keys [uri headers] :as req}]
  (swap! seen conj (select-keys req [:request-method :uri :query-string :headers]))
  (case uri
    "/idp2/clients/auth"
    (if (= (get headers "authorization") (str "Basic " (u/base64 "key-1:secret-1")))
      {:status 200 :body (json/generate-string {:token (str "bearer-" (count @seen)) :exp 9999999999})}
      {:status 401})
    "/echo-secret" {:status 200
                   :headers {"x-echo" (str (get headers "authorization"))}
                   :body (str "your key is s3cret-value-123, you sent " (get headers "authorization"))}
    "/redirect"    {:status 302 :headers {"location" "https://elsewhere.example/"}}
    "/expire"      (if (= "Bearer bearer-1" (get headers "authorization"))
                     {:status 401}
                     {:status 200 :body "refreshed"})
    {:status 200 :body "ok"}))

(def upstream (atom nil))

(use-fixtures :once
  (fn [t]
    (let [srv (server/run-server upstream-handler {:ip "127.0.0.1" :port 0 :legacy-return-value? false})]
      (reset! upstream srv)
      (try (t) (finally (server/server-stop! srv))))))

(use-fixtures :each (fn [t] (reset! seen []) (t)))

(defn- upstream-host [] (str "127.0.0.1:" (server/server-port @upstream)))

(def client (http/client {:follow-redirects :never :version :http1.1}))

(def secrets
  {"op://V/bearer/credential" "s3cret-value-123"
   "op://V/OTH 127.0.0.1/username" "key-1"
   "op://V/OTH 127.0.0.1/credential" "secret-1"})

(defn- deps []
  {:read-secret #(or (secrets (str/replace % #":\d+" "")) (throw (ex-info (str "no secret " %) {})))
   :send (partial u/http-send client)})

(defn- service [auth & {:as more}]
  (merge {:scheme "http" :allow-hosts ["127.0.0.1:*"] :auth auth} more))

(def bearer {:type :bearer :token "op://V/bearer/credential"})

(defmacro with-session [[sym svc] & body]
  `(let [~sym (u/start! {:service-name :test :service ~svc :host (upstream-host)} (deps))]
     (try ~@body (finally ((:stop ~sym))))))

(defn- call [session path & {:keys [method headers token] :or {method :get}}]
  (http/request {:client client :method method :throw false
                 :uri (str (:base-url session) path)
                 :headers (merge {"x-unlock-token" (or token (:token session))} headers)}))

;; ---------------------------------------------------------------------------

(deftest hosts
  (let [svc {:allow-hosts ["*.oth.io"] :deny-hosts ["doccla-prod.oth.io"]}]
    (is (= "doccla-dev.oth.io" (u/check-host svc "Doccla-Dev.oth.io.")))
    (doseq [h ["doccla-prod.oth.io" "DOCCLA-PROD.OTH.IO" "doccla-prod.oth.io."]]
      (is (thrown-with-msg? Exception #"blocked" (u/check-host svc h)) h))
    (doseq [h ["oth.io" "a.b.oth.io" "doccla-dev.oth.io.evil.com" "evil.com"]]
      (is (thrown-with-msg? Exception #"not in this service" (u/check-host svc h)) h))
    (doseq [h ["https://doccla-dev.oth.io" "evil.com/@doccla-dev.oth.io" "user@doccla-dev.oth.io" ""]]
      (is (thrown-with-msg? Exception #"Not a valid host" (u/check-host svc h)) h))))

(deftest blocked-host-never-reads-secrets
  (let [reads (atom 0)]
    (is (thrown? Exception
                 (u/start! {:service-name :t :host "doccla-prod.oth.io"
                            :service {:allow-hosts ["*.oth.io"] :deny-hosts ["doccla-prod.oth.io"] :auth bearer}}
                           {:read-secret (fn [_] (swap! reads inc) "x") :send (fn [_] {:status 200})})))
    (is (zero? @reads))))

(deftest session-token-required
  (with-session [s (service bearer)]
    (is (= 401 (:status (call s "/x" :token "wrong"))))
    (is (= 401 (:status (http/get (str (:base-url s) "/x") {:client client :throw false}))))
    (is (empty? @seen))))

(deftest host-header-checked
  (with-session [s (service bearer)]
    (let [port (re-find #"\d+$" (:base-url s))]
      (with-open [sock (Socket. "127.0.0.1" (parse-long port))]
        (let [out (PrintWriter. (.getOutputStream sock) true)
              in (BufferedReader. (InputStreamReader. (.getInputStream sock)))]
          (.print out (str "GET /x HTTP/1.1\r\nHost: rebound.example:" port "\r\n"
                           "X-Unlock-Token: " (:token s) "\r\nConnection: close\r\n\r\n"))
          (.flush out)
          (is (str/includes? (.readLine in) "403")))))
    (is (empty? @seen))))

(deftest injects-credential-and-strips-agent-auth
  (with-session [s (service bearer)]
    (let [r (call s "/api/thing?a=1" :method :post
                  :headers {"authorization" "Bearer agent-made-this-up"
                            "cookie" "session=abc"
                            "x-other" "kept"})]
      (is (= 200 (:status r)))
      (let [{:keys [uri query-string headers request-method]} (first @seen)]
        (is (= :post request-method))
        (is (= "/api/thing" uri))
        (is (= "a=1" query-string))
        (is (= "Bearer s3cret-value-123" (get headers "authorization")))
        (is (nil? (get headers "cookie")))
        (is (nil? (get headers "x-unlock-token")))
        (is (= "kept" (get headers "x-other")))))))

(deftest scrubs-echoed-secrets
  (with-session [s (service bearer)]
    (let [body (:body (call s "/echo-secret"))]
      (is (not (str/includes? body "s3cret-value-123")))
      (is (str/includes? body "REDACTED")))))

(deftest does-not-follow-redirects
  (with-session [s (service bearer)]
    (let [r (call s "/redirect")]
      (is (= 302 (:status r)))
      (is (= 1 (count @seen))))))

(deftest path-rules
  (let [svc {:allow [[:get "/api/patients/*"] [:any "/health"]]}]
    (is (u/allowed? svc :get "/api/patients/123"))
    (is (u/allowed? svc :post "/health"))
    (is (not (u/allowed? svc :post "/api/patients/123")))
    (is (not (u/allowed? svc :get "/api/patients/123/notes")))
    (is (not (u/allowed? svc :get "/api/patients/../admin")))
    (is (not (u/allowed? svc :get "/api/patients/%2e%2e")))
    (is (u/allowed? {} :delete "/anything"))
    (let [deep {:allow [[:get "/api/**"] [:get "/a/*/c/**.json"]]}]
      (is (u/allowed? deep :get "/api/x/y/z"))
      (is (u/allowed? deep :get "/a/b/c/d/e.json"))
      (is (not (u/allowed? deep :get "/a/b/x/c/e.json")))
      (is (not (u/allowed? deep :get "/apix")))))
  (with-session [s (service bearer :allow [[:get "/ok"]])]
    (is (= 403 (:status (call s "/nope"))))
    (is (= 200 (:status (call s "/ok"))))
    (is (= ["/ok"] (map :uri @seen)))))

(deftest oth-client-exchange
  (let [auth {:type :oth-client
              :client-key "op://V/OTH {host}/username"
              :client-secret "op://V/OTH {host}/credential"}]
    (with-session [s (service auth)]
      (is (= 200 (:status (call s "/a"))))
      (is (= 200 (:status (call s "/b"))))
      (testing "exchanges once, then reuses the token"
        (is (= ["/idp2/clients/auth" "/a" "/b"] (map :uri @seen)))
        (is (= "Bearer bearer-1" (get-in (nth @seen 1) [:headers "authorization"])))))
    (reset! seen [])
    (with-session [s (service auth)]
      (testing "a 401 forces one re-exchange and retry"
        (let [r (call s "/expire")]
          (is (= 200 (:status r)))
          (is (= ["/idp2/clients/auth" "/expire" "/idp2/clients/auth" "/expire"] (map :uri @seen)))))
      (testing "the exchanged token is scrubbed from what the agent sees"
        (let [r (call s "/echo-secret")]
          (is (not (str/includes? (:body r) "bearer-")))
          (is (not (str/includes? (get-in r [:headers "x-echo"]) "bearer-"))))))))

(deftest durations
  (is (= 1800 (u/parse-duration "30m")))
  (is (= 90 (u/parse-duration "90s")))
  (is (= 7200 (u/parse-duration "2h")))
  (is (= 300 (u/parse-duration "5")))
  (is (thrown? Exception (u/parse-duration "soon"))))

(deftest json-config
  (let [f (java.io.File/createTempFile "unlock" ".json")]
    (spit f (json/generate-string
             {:op-bin "/usr/local/bin/op"
              :services {:opentele {:allow-hosts ["*.oth.io"]
                                    :auth {:type "oth-client" :client-key "op://a" :client-secret "op://b"}
                                    :allow [["GET" "/api/**"] ["any" "/health"]]}}}))
    (let [svc (get-in (u/read-config (str f)) [:services :opentele])]
      (is (= :oth-client (get-in svc [:auth :type])))
      (is (= [[:get "/api/**"] [:any "/health"]] (:allow svc)))
      (is (u/allowed? svc :get "/api/x"))
      (is (not (u/allowed? svc :post "/api/x"))))
    (.delete f)))

(deftest integrity
  (testing "user-writable files are flagged"
    (is (seq (u/integrity-problems ["unlock.clj"]))))
  (testing "missing files are flagged"
    (is (some #(str/includes? % "does not exist") (u/integrity-problems ["/nonexistent/op"]))))
  (testing "root-owned system files pass"
    (is (empty? (u/integrity-problems ["/bin/sh"])))))
