(ns logseq.db-sync.worker.allowlist
  "Restricts sync access to an explicit set of users.

  JWTs are validated against Logseq's shared Cognito pool, so a self-hosted
  server would otherwise accept every Logseq account. `DB_SYNC_ALLOWED_USERS`
  is a comma or whitespace separated list of Cognito subs, `cognito:username`
  values, or verified email addresses. It fails closed: an unset or blank list
  denies everyone."
  (:require [clojure.string :as string]
            [lambdaisland.glogi :as log]
            [logseq.db-sync.worker.auth :as auth]
            [promesa.core :as p]))

(defn allowed-entries
  "The configured identifiers, lower-cased. Empty when nothing is configured."
  [^js env]
  (->> (string/split (or (aget env "DB_SYNC_ALLOWED_USERS") "") #"[,\s]+")
       (map string/trim)
       (remove string/blank?)
       (map string/lower-case)
       set))

(defn- claim-listed?
  [entries ^js claims k]
  (let [v (aget claims k)]
    (and (string? v)
         (not (string/blank? v))
         (contains? entries (string/lower-case (string/trim v))))))

(defn- email-verified?
  "Cognito sends this as a boolean in id tokens and as a string in some flows."
  [^js claims]
  (let [v (aget claims "email_verified")]
    (or (true? v) (= "true" v))))

(defn claims-allowed?
  "True when `claims` identify a whitelisted user.

  An email only counts when Cognito says it is verified, so an unverified
  claim cannot be used to impersonate a listed address.

  Warns when an authenticated user is turned away, since a denied user has no
  other way to discover the `sub` they need to be whitelisted by. Anonymous
  requests are not logged."
  [^js env ^js claims]
  (let [entries (allowed-entries env)
        allowed? (boolean
                  (and (some? claims)
                       (seq entries)
                       (or (claim-listed? entries claims "sub")
                           (claim-listed? entries claims "cognito:username")
                           (and (email-verified? claims)
                                (claim-listed? entries claims "email")))))]
    (when (and (some? claims) (not allowed?))
      (log/warn :db-sync/allowlist-denied
                {:sub (aget claims "sub")
                 :username (aget claims "cognito:username")
                 :email (aget claims "email")}))
    allowed?))

(defn <request-allowed?
  "Resolves true when the request carries a token for a whitelisted user.

  Verification errors propagate unchanged so upstream's error handling still
  applies."
  [request ^js env]
  (p/let [claims (auth/auth-claims request env)]
    (claims-allowed? env claims)))
