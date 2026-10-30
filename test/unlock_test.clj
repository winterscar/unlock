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

(defn- form-params [body]
  (into {} (for [pair (str/split (slurp body) #"&")
                 :let [[k v] (str/split pair #"=" 2)]]
             [(java.net.URLDecoder/decode k "UTF-8") (java.net.URLDecoder/decode v "UTF-8")])))

(defn- upstream-handler [{:keys [uri headers body] :as req}]
  (let [form (when (= "/oauth/tokens" uri) (form-params body))]
    (swap! seen conj (cond-> (select-keys req [:request-method :uri :query-string :headers])
                       form (assoc :form form)))
    (case uri
      "/auth/login"
      (if (= (get headers "authorization") (str "Basic " (u/base64 "agent-user:pw-123456")))
        {:status 200 :body (json/generate-string {:token (str "bearer-" (count @seen)) :exp 9999999999})}
        {:status 401 :body "{\"message\": \"Invalid credentials\"}"})
      "/oauth/tokens"
      (if (and (= "client_credentials" (form "grant_type"))
               (= "client-abc" (form "client_id"))
               (= "csecret-123456" (form "client_secret")))
        {:status 200 :body (json/generate-string {:access_token (str "bearer-" (count @seen))
                                                  :token_type "bearer"
                                                  :expires_in (parse-long (form "expires_in" "1800"))})}
        {:status 401 :body "{\"error\": \"invalid_client\"}"})
      "/auth/nested"
      {:status 200 :body (json/generate-string {:data {:access (str "bearer-" (count @seen))}})}
      "/echo-secret" {:status 200
                     :headers {"x-echo" (str (get headers "authorization"))}
                     :body (str "your key is s3cret-value-123, you sent " (get headers "authorization"))}
      "/redirect"    {:status 302 :headers {"location" "https://elsewhere.example/"}}
      "/expire"      (if (= "Bearer bearer-1" (get headers "authorization"))
                       {:status 401}
                       {:status 200 :body "refreshed"})
      {:status 200 :body "ok"})))

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
   "op://V/login 127.0.0.1/username" "agent-user"
   "op://V/login 127.0.0.1/password" "pw-123456"
   "op://V/login/wrong-password" "not-the-password"
   "op://V/oauth/client-id" "client-abc"
   "op://V/oauth/client-secret" "csecret-123456"})

(defn- deps []
  {:read-secret #(or (secrets (str/replace % #":\d+" "")) (throw (ex-info (str "no secret " %) {})))
   :send (partial u/http-send client)})

(defn- service [auth & {:as more}]
  (merge {:scheme "http" :allow-hosts ["127.0.0.1:*"] :auth auth} more))

(def bearer {:type :bearer :token "op://V/bearer/credential"})

(def login {:type :login
            :login-path "/auth/login"
            :username "op://V/login {host}/username"
            :password "op://V/login {host}/password"})

(def client-credentials {:type :client-credentials
                         :token-path "/oauth/tokens"
                         :client-id "op://V/oauth/client-id"
                         :client-secret "op://V/oauth/client-secret"})

(defmacro with-session [[sym svc] & body]
  `(let [~sym (u/start! {:service-name :test :service ~svc :host (upstream-host)} (deps))]
     (try ~@body (finally ((:stop ~sym))))))

(defn- call [session path & {:keys [method headers token] :or {method :get}}]
  (http/request {:client client :method method :throw false
                 :uri (str (:base-url session) path)
                 :headers (merge {"x-unlock-token" (or token (:token session))} headers)}))

;; ---------------------------------------------------------------------------

(deftest hosts
  (let [svc {:allow-hosts ["*.example.com"] :deny-hosts ["prod.example.com"]}]
    (is (= "dev.example.com" (u/check-host svc "Dev.Example.com.")))
    (doseq [h ["prod.example.com" "PROD.EXAMPLE.COM" "prod.example.com."]]
      (is (thrown-with-msg? Exception #"blocked" (u/check-host svc h)) h))
    (doseq [h ["example.com" "a.b.example.com" "dev.example.com.evil.com" "evil.com"]]
      (is (thrown-with-msg? Exception #"not in this service" (u/check-host svc h)) h))
    (doseq [h ["https://dev.example.com" "evil.com/@dev.example.com" "user@dev.example.com" ""]]
      (is (thrown-with-msg? Exception #"Not a valid host" (u/check-host svc h)) h))))

(deftest blocked-host-never-reads-secrets
  (let [reads (atom 0)]
    (is (thrown? Exception
                 (u/start! {:service-name :t :host "prod.example.com"
                            :service {:allow-hosts ["*.example.com"] :deny-hosts ["prod.example.com"] :auth bearer}}
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

(deftest login-exchange
  (with-session [s (service login)]
    (is (= 200 (:status (call s "/a"))))
    (is (= 200 (:status (call s "/b"))))
    (testing "logs in once, then reuses the token"
      (is (= ["/auth/login" "/a" "/b"] (map :uri @seen)))
      (is (= "Bearer bearer-1" (get-in (nth @seen 1) [:headers "authorization"])))))
  (reset! seen [])
  (with-session [s (service login)]
    (testing "a 401 forces one fresh login and retry"
      (let [r (call s "/expire")]
        (is (= 200 (:status r)))
        (is (= ["/auth/login" "/expire" "/auth/login" "/expire"] (map :uri @seen)))))
    (testing "the token and the Basic credentials are scrubbed from what the agent sees"
      (let [r (call s "/echo-secret")]
        (is (not (str/includes? (:body r) "bearer-")))
        (is (not (str/includes? (get-in r [:headers "x-echo"]) "bearer-")))
        (is (not (str/includes? (:body r) (u/base64 "agent-user:pw-123456"))))))))

(deftest login-token-field
  (with-session [s (service (assoc login :login-path "/auth/nested" :token-field "data.access"))]
    (is (= 200 (:status (call s "/a"))))
    (is (= "Bearer bearer-1" (get-in (second @seen) [:headers "authorization"])))))

(deftest failed-login-is-not-retried
  ;; Services often count failed logins towards locking the account.
  (with-session [s (service (assoc login :password "op://V/login/wrong-password"))]
    (let [r1 (call s "/a")
          r2 (call s "/b")]
      (is (= 502 (:status r1)))
      (is (str/includes? (:body r1) "not retrying"))
      (is (= 502 (:status r2)))
      (is (= ["/auth/login"] (map :uri @seen)) "one login attempt, and no upstream calls"))))

(deftest client-credentials-exchange
  (with-session [s (service (assoc client-credentials :scope "read"))]
    (is (= 200 (:status (call s "/a"))))
    (is (= 200 (:status (call s "/b"))))
    (testing "fetches a token once with a form-encoded grant, then reuses it"
      (is (= ["/oauth/tokens" "/a" "/b"] (map :uri @seen)))
      (is (= :post (:request-method (first @seen))))
      (is (= {"grant_type" "client_credentials" "client_id" "client-abc"
              "client_secret" "csecret-123456" "scope" "read"}
             (:form (first @seen))))
      (is (= "Bearer bearer-1" (get-in (nth @seen 1) [:headers "authorization"]))))
    (testing "the token and client secret are scrubbed from what the agent sees"
      (let [r (call s "/echo-secret")]
        (is (not (str/includes? (get-in r [:headers "x-echo"]) "bearer-")))
        (is (not (str/includes? (:body r) "bearer-"))))))
  (reset! seen [])
  (with-session [s (service client-credentials)]
    (testing "a 401 forces one fresh token and retry"
      (is (= 200 (:status (call s "/expire"))))
      (is (= ["/oauth/tokens" "/expire" "/oauth/tokens" "/expire"] (map :uri @seen))))))

(deftest client-credentials-expiry
  ;; expires_in is relative; a token within a minute of expiring is replaced.
  (with-session [s (service (assoc client-credentials :expires-in 30))]
    (call s "/a")
    (call s "/b")
    (is (= ["/oauth/tokens" "/a" "/oauth/tokens" "/b"] (map :uri @seen)))
    (is (= "30" (get-in (first @seen) [:form "expires_in"])))))

(deftest failed-client-credentials-is-not-retried
  (with-session [s (service (assoc client-credentials :client-secret "op://V/login/wrong-password"))]
    (let [r1 (call s "/a")
          r2 (call s "/b")]
      (is (= 502 (:status r1)))
      (is (str/includes? (:body r1) "token request at /oauth/tokens failed (HTTP 401)"))
      (is (= 502 (:status r2)))
      (is (= ["/oauth/tokens"] (map :uri @seen))))))

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
              :services {:svc {:allow-hosts ["*.example.com"]
                               :auth {:type "login" :login-method "POST" :login-path "/l"
                                      :username "op://a" :password "op://b"}
                               :allow [["GET" "/api/**"] ["any" "/health"]]}}}))
    (let [svc (get-in (u/read-config (str f)) [:services :svc])]
      (is (= :login (get-in svc [:auth :type])))
      (is (= :post (get-in svc [:auth :login-method])))
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
