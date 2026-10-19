#!/usr/bin/env bb

;; unlock: time-boxed, single-service credential-injecting proxy.
;;
;; You run it in your own terminal. It reads the service's credentials from
;; 1Password (Touch ID), holds them in memory only, and serves a proxy on
;; 127.0.0.1 that adds them to requests bound for one upstream host. The agent
;; gets a proxy URL and a session token that is worthless anywhere else. When
;; the timer runs out, or you hit Ctrl-C, the process exits and the credential
;; is gone.
;;
;; It has no admin API, no policy reload, and no on-disk secret. Install the
;; script and its config root-owned (the nix module or install.sh) so a same-user
;; agent cannot edit them; it refuses to unlock anything when they are writable.

(ns unlock
  (:require [babashka.cli :as cli]
            [babashka.fs :as fs]
            [babashka.http-client :as http]
            [babashka.process :as p]
            [cheshire.core :as json]
            [clojure.edn :as edn]
            [clojure.string :as str]
            [org.httpkit.server :as server])
  (:import (java.nio.charset StandardCharsets)
           (java.nio.file Files LinkOption)
           (java.nio.file.attribute PosixFilePermission)
           (java.security MessageDigest SecureRandom)
           (java.time Instant)
           (java.util Base64)))

(def default-config
  (or (first (filter fs/exists? ["/etc/unlock/services.json" "/etc/unlock/services.edn"]))
      "/etc/unlock/services.edn"))
(def default-op-bin "/usr/local/bin/op")
(def state-dir (fs/path (fs/home) ".local" "state" "unlock"))

;; ---------------------------------------------------------------------------
;; Small helpers

(defn- now-s [] (.getEpochSecond (Instant/now)))

(defn- random-token []
  (let [bytes (byte-array 32)]
    (.nextBytes (SecureRandom.) bytes)
    (str "unl_" (.encodeToString (.withoutPadding (Base64/getUrlEncoder)) bytes))))

(defn- constant-time= [^String a ^String b]
  (and a b (MessageDigest/isEqual (.getBytes a StandardCharsets/UTF_8)
                                  (.getBytes b StandardCharsets/UTF_8))))

(defn base64 [^String s]
  (.encodeToString (Base64/getEncoder) (.getBytes s StandardCharsets/UTF_8)))

(defn parse-duration
  "\"30m\" -> 1800. Accepts s, m, h suffixes; a bare number is minutes."
  [s]
  (let [[_ n unit] (re-matches #"(\d+)([smh]?)" (str s))]
    (when-not n
      (throw (ex-info (str "Bad duration: " s " (use e.g. 90s, 30m, 2h)") {})))
    (* (parse-long n) (case unit "s" 1 "h" 3600 60))))

;; ---------------------------------------------------------------------------
;; Hosts

(defn normalise-host
  "Lower-cased host[:port] with any trailing dot removed, or nil if it is not
  a plain hostname. Rejects anything carrying a scheme, path, userinfo, etc."
  [s]
  (let [h (-> (str s) str/trim str/lower-case (str/replace #"\.(?=(:\d+)?$)" ""))]
    (when (re-matches #"[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*(:\d{1,5})?" h)
      h)))

(defn- host-glob->regex
  "\"*.example.com\" -> a regex where * matches exactly one DNS label."
  [glob]
  (re-pattern (str/join "[a-z0-9-]+" (map #(java.util.regex.Pattern/quote %)
                                          (str/split (str/lower-case glob) #"\*" -1)))))

(defn- host-matches? [globs host]
  (some #(re-matches (host-glob->regex %) host) globs))

(defn check-host
  "Returns the normalised host if the service may be pointed at it, else throws."
  [{:keys [allow-hosts deny-hosts]} host]
  (let [h (normalise-host host)]
    (cond
      (nil? h)
      (throw (ex-info (str "Not a valid host: " (pr-str host)) {}))

      (host-matches? deny-hosts h)
      (throw (ex-info (str h " is blocked for this service") {}))

      (not (host-matches? allow-hosts h))
      (throw (ex-info (str h " is not in this service's :allow-hosts " (pr-str allow-hosts)) {}))

      :else h)))

;; ---------------------------------------------------------------------------
;; Path rules

(defn- path-glob->regex
  "\"/api/**\" -> ** matches anything, * matches within one segment."
  [glob]
  (re-pattern (apply str (map (fn [token]
                                ({"**" ".*" "*" "[^/]*"} token (java.util.regex.Pattern/quote token)))
                              (re-seq #"\*\*|\*|[^*]+" glob)))))

(defn- suspicious-path?
  "Paths whose meaning could differ between our glob match and the upstream's
  router: dot segments, encoded separators or dots, backslashes."
  [path]
  (or (re-find #"(^|/)\.\.?(/|$)" path)
      (re-find #"(?i)%(2e|2f|5c)" path)
      (str/includes? path "\\")))

(defn allowed?
  "With no :allow rules every method and path is permitted. Otherwise a rule
  is [method path-glob], method being a keyword or :any."
  [{:keys [allow]} method path]
  (or (nil? allow)
      (and (not (suspicious-path? path))
           (some (fn [[m glob]]
                   (and (or (= m :any) (= m method))
                        (re-matches (path-glob->regex glob) path)))
                 allow))))

;; ---------------------------------------------------------------------------
;; Secrets

(defn op-read
  "Reads one secret reference with the 1Password CLI. The value comes back on
  stdout; it never goes into an argument or the environment."
  [op-bin ref]
  (let [{:keys [exit out err]} (p/shell {:out :string :err :string :continue true}
                                        op-bin "read" "--no-newline" ref)]
    (when-not (zero? exit)
      (throw (ex-info (str "op read failed for " ref ": " (str/trim err)) {})))
    (when (str/blank? out)
      (throw (ex-info (str "op read returned an empty value for " ref) {})))
    out))

(defn- expand-ref [ref host]
  (str/replace ref "{host}" host))

(def ^:private ref-keys
  {:bearer     [:token]
   :basic      [:username :password]
   :header     [:value]
   :login      [:username :password]})

(defn resolve-secrets
  "Reads every secret the service's :auth needs. Returns the auth map with the
  op:// references replaced by their values."
  [{:keys [auth]} host read-secret]
  (let [ks (or (ref-keys (:type auth))
               (throw (ex-info (str "Unknown :auth :type " (pr-str (:type auth))) {})))]
    (reduce (fn [a k]
              (let [ref (or (get auth k)
                            (throw (ex-info (str ":auth is missing " k) {})))]
                (assoc a k (read-secret (expand-ref ref host)))))
            auth ks)))

;; ---------------------------------------------------------------------------
;; Credentials on the wire

(defn- secret-strings
  "Every string whose appearance in a response would leak a credential."
  [auth bearer]
  (->> (concat (vals (select-keys auth (ref-keys (:type auth)))) [bearer])
       (concat (when (= :basic (:type auth))
                 [(base64 (str (:username auth) ":" (:password auth)))]))
       (concat (when (= :login (:type auth))
                 [(base64 (str (:username auth) ":" (:password auth)))]))
       (remove nil?)
       (filter #(>= (count %) 6))
       distinct))

(defn- json-field
  "\"a.b\" -> (get-in m [:a :b])."
  [m dotted]
  (get-in m (map keyword (str/split dotted #"\."))))

(defn- login!
  "Swaps Basic credentials for a Bearer token at the service's :login-path.
  Many services count failed logins towards locking the account, so a failure
  is remembered in `token-cache` and no further login is attempted until
  unlock is restarted."
  [send base-url {:keys [login-path login-method token-field exp-field username password]} token-cache]
  (let [resp (send {:method (or login-method :get)
                    :uri (str base-url login-path)
                    :headers {"authorization" (str "Basic " (base64 (str username ":" password)))
                              "accept" "application/json"}})
        body (when (= 200 (:status resp))
               (json/parse-string (String. ^bytes (:body resp) StandardCharsets/UTF_8) true))
        token (some-> body (json-field (or token-field "token")))]
    (when-not token
      (let [msg (str "login at " login-path " failed (HTTP " (:status resp)
                     (when (= 200 (:status resp)) ", no token in response")
                     "); not retrying until unlock is restarted")]
        (swap! token-cache assoc :failed msg)
        (throw (ex-info msg {}))))
    ;; With no expiry to go on, the token is reused until the upstream 401s.
    {:token token
     :exp (or (some-> body (json-field (or exp-field "exp"))) Long/MAX_VALUE)}))

(defn- auth-header
  "[header-name value] to inject, logging in again when a :login token is close
  to expiry or when `force?` says the upstream just rejected it."
  [{:keys [auth base-url send token-cache]} force?]
  (case (:type auth)
    :bearer ["authorization" (str "Bearer " (:token auth))]
    :basic  ["authorization" (str "Basic " (base64 (str (:username auth) ":" (:password auth))))]
    :header [(str/lower-case (:name auth)) (str/replace (or (:format auth) "{}") "{}" (:value auth))]
    :login
    (let [{:keys [token exp failed]} @token-cache]
      (cond
        failed (throw (ex-info failed {}))
        (and token (not force?) (> exp (+ (now-s) 60))) ["authorization" (str "Bearer " token)]
        :else
        (let [fresh (login! send base-url auth token-cache)]
          (reset! token-cache fresh)
          ["authorization" (str "Bearer " (:token fresh))])))))

(def ^:private hop-by-hop
  #{"connection" "keep-alive" "proxy-authenticate" "proxy-authorization" "te"
    "trailer" "transfer-encoding" "upgrade" "http2-settings" "host"
    "content-length" "expect"})

(def ^:private never-forward
  ;; Anything the agent sends that could carry or impersonate a credential.
  #{"authorization" "cookie" "x-unlock-token" "accept-encoding"})

(defn- connection-listed [headers]
  (set (map (comp str/lower-case str/trim)
            (str/split (str (get headers "connection" "")) #","))))

(defn- outbound-headers [headers]
  (let [drop? (into (into hop-by-hop never-forward) (connection-listed headers))]
    (into {"accept-encoding" "identity"}
          (remove (fn [[k _]] (drop? (str/lower-case k))))
          headers)))

(defn- scrub
  "Replaces any credential appearing in `s`. Bodies are scrubbed as ISO-8859-1
  so arbitrary bytes round-trip unchanged."
  [secrets ^String s]
  (reduce #(str/replace %1 %2 "[REDACTED BY UNLOCK]") s secrets))

(defn- scrub-bytes [secrets ^bytes body]
  (let [latin #(String. ^bytes % StandardCharsets/ISO_8859_1)
        s (latin body)
        needles (map #(latin (.getBytes ^String % StandardCharsets/UTF_8)) secrets)]
    (if (some #(str/includes? s %) needles)
      (.getBytes ^String (scrub needles s) StandardCharsets/ISO_8859_1)
      body)))

(defn- inbound-headers [secrets headers]
  (into {}
        (keep (fn [[k v]]
                (let [k (str/lower-case (name k))
                      v (if (sequential? v) (str/join ", " v) (str v))]
                  (when-not (hop-by-hop k)
                    [k (scrub secrets v)]))))
        headers))

;; ---------------------------------------------------------------------------
;; The proxy

(defn- deny [status msg]
  {:status status
   :headers {"content-type" "text/plain"}
   :body (str "unlock: " msg "\n")})

(defn- read-body [body]
  (cond
    (nil? body) nil
    (bytes? body) body
    (string? body) (.getBytes ^String body StandardCharsets/UTF_8)
    :else (.readAllBytes ^java.io.InputStream body)))

(defn- log [& parts]
  (println (str (.toString (Instant/now)) " " (str/join " " parts)))
  (flush))

(defn handler
  [{:keys [service port session-token base-url send] :as ctx}]
  (let [local-hosts #{(str "127.0.0.1:" port) (str "localhost:" port)}]
    (fn [{:keys [request-method uri query-string headers body]}]
      (let [started (System/currentTimeMillis)
            method-s (str/upper-case (name request-method))
            response
            (cond
              ;; A page in your browser resolving some name to 127.0.0.1 would
              ;; arrive with its own Host header.
              (not (local-hosts (get headers "host")))
              (deny 403 "bad Host header")

              (not (constant-time= session-token (get headers "x-unlock-token")))
              (deny 401 "missing or wrong X-Unlock-Token")

              (not (allowed? service request-method uri))
              (deny 403 (str method-s " " uri " is not allowed for this service"))

              :else
              (let [body (read-body body)
                    out-headers (outbound-headers headers)
                    attempt (fn [force?]
                              (let [[hk hv] (auth-header ctx force?)]
                                (send {:method request-method
                                       :uri (str base-url uri (when query-string (str "?" query-string)))
                                       :headers (assoc out-headers hk hv)
                                       :body body})))
                    resp (try
                           (let [r (attempt false)]
                             (if (and (= 401 (:status r)) (= :login (get-in service [:auth :type])))
                               (attempt true)
                               r))
                           (catch clojure.lang.ExceptionInfo e
                             (log "ERROR" (ex-message e))
                             (deny 502 (ex-message e))))
                    secrets (secret-strings (:auth ctx) (:token @(:token-cache ctx)))]
                {:status (:status resp)
                 :headers (inbound-headers secrets (:headers resp))
                 :body (some->> (:body resp) read-body (scrub-bytes secrets))}))]
        (log method-s uri "->" (:status response) (str (- (System/currentTimeMillis) started) "ms"))
        response))))

(defn http-send
  "Sends one request upstream. Redirects are returned to the agent rather than
  followed, so the credential never goes anywhere but the unlocked host."
  [client req]
  (http/request (merge req {:client client :throw false :as :bytes :timeout 60000})))

(defn start!
  "Starts the proxy. `deps` supplies :read-secret and :send, which is how the
  dry run and the tests swap in mocks. Returns a map describing the session
  with a :stop fn."
  [{:keys [service-name service host port]} {:keys [read-secret send]}]
  (let [host (check-host service host)
        base-url (str (or (:scheme service) "https") "://" host)
        auth (resolve-secrets service host read-secret)
        session-token (random-token)
        ctx-port (promise)
        ctx {:service service :base-url base-url :send send :auth auth
             :token-cache (atom {}) :session-token session-token}
        handle (delay (handler (assoc ctx :port @ctx-port)))
        srv (server/run-server
             (fn [req] (@handle req))
             {:ip "127.0.0.1" :port (or port 0) :legacy-return-value? false
              :max-body (* 32 1024 1024)})
        bound (server/server-port srv)]
    (deliver ctx-port bound)
    {:service service-name
     :upstream base-url
     :base-url (str "http://127.0.0.1:" bound)
     :token session-token
     :stop #(server/server-stop! srv)}))

;; ---------------------------------------------------------------------------
;; Config

(defn normalise-config
  "JSON configs (as nix writes them) arrive with strings where EDN has
  keywords: auth types and allow-rule methods."
  [config]
  (update config :services update-vals
          (fn [svc]
            (cond-> svc
              (:auth svc)  (update-in [:auth :type] keyword)
              (get-in svc [:auth :login-method])
              (update-in [:auth :login-method] (comp keyword str/lower-case name))
              (:allow svc) (update :allow (partial mapv (fn [[m glob]]
                                                          [(keyword (str/lower-case (name m))) glob])))))))

(defn read-config [path]
  (normalise-config
   (if (str/ends-with? (str path) ".json")
     (json/parse-string (slurp path) true)
     (edn/read-string (slurp path)))))

;; ---------------------------------------------------------------------------
;; Install integrity

(defn- writable-by-others?
  "True unless `path` is owned by root and writable by nobody but its owner."
  [path]
  (let [p (fs/path path)
        owner (.getName (Files/getOwner p (make-array LinkOption 0)))
        perms (Files/getPosixFilePermissions p (make-array LinkOption 0))]
    (or (not= "root" owner)
        (contains? perms PosixFilePermission/GROUP_WRITE)
        (contains? perms PosixFilePermission/OTHERS_WRITE))))

(defn- in-store? [p] (str/starts-with? (str p) "/nix/store/"))

(defn integrity-problems
  "Anything an agent running as you could rewrite to steal the credential:
  this script, its config, the op binary, and the directories holding them.
  Checks both the path as given and where its symlinks lead. A nix store path
  is immutable, so its parent (the group-writable store itself) is not checked."
  [paths]
  (distinct
   (for [path paths
         p (if (fs/exists? path) (distinct [(fs/path path) (fs/canonicalize path)]) [path])
         q [p (when-not (in-store? p) (fs/parent p))]
         :when (and q (or (not (fs/exists? q)) (writable-by-others? q)))]
     (if (fs/exists? q)
       (str (fs/canonicalize q) " is not root-owned and write-protected")
       (str q " does not exist")))))

;; ---------------------------------------------------------------------------
;; CLI

(def cli-spec
  {:for     {:desc "How long to stay unlocked (90s, 30m, 2h)" :default "30m"}
   :port    {:desc "Local port (default: any free port)" :coerce :long}
   :config  {:desc "Services config" :default default-config}
   :dry-run {:desc "Mock 1Password and the upstream; nothing leaves this machine" :coerce :boolean}
   :help    {:desc "Show help" :alias :h :coerce :boolean}})

(defn- usage [services]
  (str "Usage: unlock <service> [host] [options]\n\n"
       (cli/format-opts {:spec cli-spec})
       (when (seq services)
         (str "\n\nServices: " (str/join ", " (map name (keys services)))))))

(defn- dry-run-deps [service]
  {:read-secret (fn [ref] (str "dry-run-secret-for:" ref))
   :send (fn [{:keys [method uri headers]}]
           (if (and (= :login (get-in service [:auth :type]))
                    (str/ends-with? (first (str/split uri #"\?")) (get-in service [:auth :login-path])))
             {:status 200 :headers {"content-type" "application/json"}
              :body (.getBytes (json/generate-string {:token "dry-run-bearer" :exp (+ (now-s) 1800)}))}
             {:status 200
              :headers {"content-type" "application/json"}
              :body (.getBytes (json/generate-string
                                {:dry-run true
                                 :would-send {:method method :uri uri
                                              :headers (sort (keys headers))}}))}))})

(defn- write-state! [session expires-at]
  (fs/create-dirs state-dir)
  (let [f (fs/file state-dir (str (name (:service session)) ".json"))]
    (spit f "")
    (fs/set-posix-file-permissions f "rw-------")
    (spit f (json/generate-string (-> (select-keys session [:service :upstream :base-url :token])
                                      (assoc :expires-at (str (Instant/ofEpochSecond expires-at))))
                                  {:pretty true}))
    f))

(defn -main [& args]
  (let [{:keys [args opts]} (cli/parse-args args {:spec cli-spec})
        config (when (fs/exists? (:config opts)) (read-config (:config opts)))
        services (:services config)
        [service-name host] args
        service (get services (keyword service-name))]
    (when (or (:help opts) (nil? service-name))
      (println (usage services))
      (System/exit (if (:help opts) 0 1)))
    (when-not config
      (binding [*out* *err*] (println "No config at" (:config opts)))
      (System/exit 1))
    (when-not service
      (binding [*out* *err*] (println "Unknown service" service-name) (println (usage services)))
      (System/exit 1))
    (let [op-bin (or (:op-bin config) default-op-bin)
          problems (integrity-problems [(System/getProperty "babashka.file") (:config opts) op-bin])
          seconds (parse-duration (:for opts))
          deps (if (:dry-run opts)
                 (dry-run-deps service)
                 (let [client (http/client {:follow-redirects :never :version :http1.1})]
                   {:read-secret (partial op-read op-bin)
                    :send (partial http-send client)}))]
      (when (seq problems)
        (binding [*out* *err*]
          (println (if (:dry-run opts) "WARNING (ignored for --dry-run):" "Refusing to unlock:"))
          (doseq [p problems] (println " -" p))
          (when-not (:dry-run opts)
            (println "Run install.sh to install unlock and its config root-owned.")
            (System/exit 1))))
      (try
        (let [session (start! {:service-name (keyword service-name)
                               :service service
                               :host (or host (:default-host service))
                               :port (:port opts)}
                              deps)
              expires-at (+ (now-s) seconds)
              state-file (write-state! session expires-at)
              lock! (fn []
                      ((:stop session))
                      (fs/delete-if-exists state-file))]
          (.addShutdownHook (Runtime/getRuntime) (Thread. ^Runnable lock!))
          (println (str "Unlocked " service-name " -> " (:upstream session)
                        (when (:dry-run opts) " (DRY RUN)")))
          (println (str "  proxy:   " (:base-url session)))
          (println (str "  header:  X-Unlock-Token (in " state-file ")"))
          (println (str "  expires: " (Instant/ofEpochSecond expires-at) "  (Ctrl-C to lock now)"))
          (println)
          (flush)
          (Thread/sleep (* 1000 seconds))
          (println "Time's up; locked.")
          (System/exit 0))
        (catch clojure.lang.ExceptionInfo e
          (binding [*out* *err*] (println "unlock:" (ex-message e)))
          (System/exit 1))))))

(when (= *file* (System/getProperty "babashka.file"))
  (apply -main *command-line-args*))
