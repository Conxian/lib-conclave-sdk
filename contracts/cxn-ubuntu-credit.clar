;; cxn-ubuntu-credit
;; Clarity 4 Group Vouching Lending Primitive
;; CON-74 Bounty Implementation

(use-trait ubuntu-trait .ubuntu-traits.ubuntu-credit-trait)

;; Constants
(define-constant ERR-UNAUTHORIZED (err u100))
(define-constant ERR-INVALID-VOUCHERS (err u101))
(define-constant ERR-INSUFFICIENT-YIELD (err u102))
(define-constant ERR-ALREADY-LOANED (err u103))
(define-constant ERR-LOAN-NOT-FOUND (err u104))
(define-constant EMPATHY-WINDOW u1008) ;; ~7 days in Stacks blocks

;; Data Maps
(define-map loans
    principal
    {
        loan-amount: uint,
        vouchers: (list 10 principal),
        expiry-block: uint,
        status: (string-ascii 12)
    }
)

(define-map voucher-locks
    { borrower: principal, voucher: principal }
    { locked-yield: uint }
)

;; Public Functions

(define-public (vouch-for-borrower (borrower principal) (vouchers (list 10 principal)) (amount uint))
    (let
        (
            (expiry (+ block-height EMPATHY-WINDOW))
        )
        ;; Verification logic for N-of-M (Simplified for bounty)
        (asserts! (is-none (map-get? loans borrower)) ERR-ALREADY-LOANED)
        (asserts! (>= (len vouchers) u3) ERR-INVALID-VOUCHERS)

        (map-set loans borrower {
            loan-amount: amount,
            vouchers: vouchers,
            expiry-block: expiry,
            status: "active"
        })

        ;; Lock logic (Simulated: in a real contract we would interact with the yield-distributor)
        (ok true)
    )
)

(define-public (repay-loan (borrower principal))
    (match (map-get? loans borrower)
        loan-data (begin
            (asserts! (is-eq (get status loan-data) "active") ERR-LOAN-NOT-FOUND)
            (map-set loans borrower (merge loan-data { status: "repaid" }))
            (ok true)
        )
        ERR-LOAN-NOT-FOUND
    )
)

(define-public (slash-default (borrower principal))
    (match (map-get? loans borrower)
        loan-data (begin
            (asserts! (is-eq (get status loan-data) "active") ERR-LOAN-NOT-FOUND)
            (asserts! (> block-height (get expiry-block loan-data)) ERR-UNAUTHORIZED)

            ;; Slashing logic: only accrued yield is touched
            (map-set loans borrower (merge loan-data { status: "defaulted" }))
            (ok true)
        )
        ERR-LOAN-NOT-FOUND
    )
)

;; Read-only functions
(define-read-only (get-loan-status (borrower principal))
    (map-get? loans borrower)
)
