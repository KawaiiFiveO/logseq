(ns logseq.db-sync.worker-allowlist-test
  (:require [cljs.test :refer [async deftest is testing]]
            [logseq.common.authorization :as authorization]
            [logseq.db-sync.worker.allowlist :as allowlist]
            [promesa.core :as p]))

(def ^:private claims
  #js {"sub" "us-east-1:11111111-2222-3333-4444-555555555555"
       "cognito:username" "Alice"
       "email" "Alice@Example.com"
       "email_verified" true})

(deftest allowed-entries-parsing-test
  (testing "splits on commas and whitespace, trims, lower-cases"
    (is (= #{"alice" "bob" "carol"}
           (allowlist/allowed-entries #js {"DB_SYNC_ALLOWED_USERS" " Alice, bob\ncarol , "}))))
  (testing "nothing configured yields an empty set"
    (is (empty? (allowlist/allowed-entries #js {})))
    (is (empty? (allowlist/allowed-entries #js {"DB_SYNC_ALLOWED_USERS" ""})))
    (is (empty? (allowlist/allowed-entries #js {"DB_SYNC_ALLOWED_USERS" " , "})))))

(deftest claims-allowed-fails-closed-test
  (testing "no whitelist configured denies every user"
    (is (not (allowlist/claims-allowed? #js {} claims)))
    (is (not (allowlist/claims-allowed? #js {"DB_SYNC_ALLOWED_USERS" ""} claims)))
    (is (not (allowlist/claims-allowed? #js {"DB_SYNC_ALLOWED_USERS" " , "} claims))))
  (testing "nil claims are denied even with a whitelist"
    (is (not (allowlist/claims-allowed? #js {"DB_SYNC_ALLOWED_USERS" "alice"} nil)))))

(deftest claims-allowed-matches-identifiers-test
  (testing "cognito sub"
    (is (allowlist/claims-allowed?
         #js {"DB_SYNC_ALLOWED_USERS" "us-east-1:11111111-2222-3333-4444-555555555555"}
         claims)))
  (testing "cognito:username, case-insensitively"
    (is (allowlist/claims-allowed? #js {"DB_SYNC_ALLOWED_USERS" "alice"} claims)))
  (testing "verified email, case-insensitively"
    (is (allowlist/claims-allowed? #js {"DB_SYNC_ALLOWED_USERS" "alice@example.com"} claims)))
  (testing "one match in a longer list is enough"
    (is (allowlist/claims-allowed? #js {"DB_SYNC_ALLOWED_USERS" "bob, alice, carol"} claims)))
  (testing "an unlisted user is denied"
    (is (not (allowlist/claims-allowed? #js {"DB_SYNC_ALLOWED_USERS" "bob, carol"} claims)))))

(deftest claims-allowed-requires-verified-email-test
  (let [unverified #js {"sub" "us-east-1:other"
                        "cognito:username" "mallory"
                        "email" "alice@example.com"
                        "email_verified" false}
        env #js {"DB_SYNC_ALLOWED_USERS" "alice@example.com"}]
    (testing "an unverified email cannot claim a listed address"
      (is (not (allowlist/claims-allowed? env unverified))))
    (testing "a missing email_verified claim is treated as unverified"
      (is (not (allowlist/claims-allowed? env #js {"email" "alice@example.com"}))))
    (testing "cognito's string form of email_verified is accepted"
      (is (allowlist/claims-allowed? env #js {"email" "alice@example.com"
                                              "email_verified" "true"})))))

(deftest claims-allowed-ignores-blank-claims-test
  (testing "a blank claim never matches a blank-ish entry"
    (is (not (allowlist/claims-allowed? #js {"DB_SYNC_ALLOWED_USERS" "alice"}
                                        #js {"sub" "" "cognito:username" nil})))))

(deftest request-allowed-uses-verified-claims-test
  (async done
         (let [request (js/Request. "http://localhost/graphs"
                                    #js {:headers #js {"authorization" "Bearer good-token"}})
               env #js {"DB_SYNC_ALLOWED_USERS" "alice"}]
           (-> (p/with-redefs [authorization/verify-jwt
                               (fn [_token _env]
                                 (js/Promise.resolve #js {"cognito:username" "alice"}))]
                 (p/let [allowed? (allowlist/<request-allowed? request env)]
                   (is (true? allowed?))))
               (p/then (fn [] (done)))
               (p/catch (fn [error]
                          (is false (str error))
                          (done)))))))

(deftest request-allowed-denies-unlisted-user-test
  (async done
         (let [request (js/Request. "http://localhost/graphs"
                                    #js {:headers #js {"authorization" "Bearer good-token"}})
               env #js {"DB_SYNC_ALLOWED_USERS" "alice"}]
           (-> (p/with-redefs [authorization/verify-jwt
                               (fn [_token _env]
                                 (js/Promise.resolve #js {"cognito:username" "mallory"}))]
                 (p/let [allowed? (allowlist/<request-allowed? request env)]
                   (is (false? allowed?))))
               (p/then (fn [] (done)))
               (p/catch (fn [error]
                          (is false (str error))
                          (done)))))))

(deftest request-allowed-denies-anonymous-request-test
  (async done
         (let [request (js/Request. "http://localhost/graphs")
               env #js {"DB_SYNC_ALLOWED_USERS" "alice"}]
           (-> (p/let [allowed? (allowlist/<request-allowed? request env)]
                 (is (false? allowed?)))
               (p/then (fn [] (done)))
               (p/catch (fn [error]
                          (is false (str error))
                          (done)))))))
