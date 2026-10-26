;; Build with the authenticated pinned channel and -L packaging/guix.
(use-modules (gnu) (gnu services ssh) (gnu services networking)
             (gnu packages admin) (gnu packages base) (gnu packages compression)
             (gnu packages curl) (gnu packages gnupg) (gnu packages python) (gnu packages certs)
             (httpjet packages) (httpjet services) (ice-9 textual-ports)
             (guix gexp) (guix utils) (guix packages) (srfi srfi-13))

(define package-lock
  (or (getenv "HTTPJET_GUIX_RELEASE_LOCK")
      (error "HTTPJET_GUIX_RELEASE_LOCK must name the authenticated generated package lock")))
(define ssh-key-file
  (or (getenv "HTTPJET_QUALIFICATION_SSH_KEY")
      (error "HTTPJET_QUALIFICATION_SSH_KEY must name the temporary public SSH key")))
(define candidate (load package-lock))
(define variant (or (getenv "HTTPJET_GUIX_VARIANT") "candidate"))
(define active-package
  (if (string=? variant "baseline")
      (if (getenv "HTTPJET_GUIX_BASELINE_LOCK")
          (load (getenv "HTTPJET_GUIX_BASELINE_LOCK"))
          (package (inherit candidate) (name "httpjet-first-release-fixture")
                   (version (string-append (package-version candidate) "-fixture"))))
      candidate))
(define test-certificate (or (getenv "HTTPJET_QUALIFICATION_CA") (getenv "HTTPJET_GUIX_TEST_CA")))
(define ssh-key (plain-file "qualification.pub" (call-with-input-file ssh-key-file get-string-all)))
(define arm? (string-prefix? "aarch64" (or (getenv "HTTPJET_GUIX_SYSTEM") (%current-system))))

(operating-system
  (host-name "httpjet-qualification")
  (timezone "Etc/UTC") (locale "en_US.utf8")
  (bootloader
   (bootloader-configuration
    (bootloader (if arm? grub-efi-bootloader grub-bootloader))
    (targets (if arm? '("/boot/efi") '("/dev/vda")))))
  (file-systems
   (append
    (list (file-system (mount-point "/") (device (file-system-label "Guix_image")) (type "ext4")))
    (if arm? (list (file-system (mount-point "/boot/efi") (device (file-system-label "GNU-ESP")) (type "vfat"))) '())
    %base-file-systems))
  (users
   (cons (user-account
          (name "qualifier") (comment "Disposable qualification account")
          (group "users") (supplementary-groups '("wheel"))
          (home-directory "/home/qualifier"))
         %base-user-accounts))
  (hosts-file (plain-file "hosts" "127.0.0.1 localhost\n::1 localhost\n10.0.2.2 httpjet-qualification.local\n"))
  (sudoers-file (plain-file "sudoers" "root ALL=(ALL) ALL\n%wheel ALL=(ALL) NOPASSWD: ALL\n"))
  (packages (append (list python curl gnupg util-linux tar gzip nss-certs) %base-packages))
  (services
   (append
    (list
     (service openssh-service-type
              (openssh-configuration
               (password-authentication? #f) (permit-root-login 'prohibit-password)
               (authorized-keys `(("qualifier" ,ssh-key)))))
     (service dhcp-client-service-type))
    (if (string=? variant "disabled") '()
        (list (service httpjet-service-type (httpjet-configuration (package active-package)))))
    (if test-certificate
        (list (simple-service
               'httpjet-qualification-ca etc-service-type
               `(("httpjet-qualification/certs/public.pem" ,(file-append nss-certs "/etc/ssl/certs/ca-certificates.crt"))
                 ("httpjet-qualification/certs/test.pem" ,(local-file test-certificate "httpjet-test-ca.pem")))))
        '())
    %base-services)))
