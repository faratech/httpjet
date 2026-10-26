(define-module (httpjet services)
  #:use-module (gnu services)
  #:use-module (gnu services base)
  #:use-module (gnu services shepherd)
  #:use-module (gnu system accounts)
  #:use-module (gnu system privilege)
  #:use-module (gnu packages admin)
  #:use-module (gnu packages base)
  #:use-module (gnu packages linux)
  #:use-module (guix gexp)
  #:use-module (guix records)
  #:use-module (ice-9 match)
  #:export (httpjet-configuration httpjet-service-type))

(define-record-type* <httpjet-configuration>
  httpjet-configuration make-httpjet-configuration httpjet-configuration?
  (package httpjet-configuration-package)
  (config-root httpjet-configuration-config-root (default "/etc/httpjet"))
  (http-address httpjet-configuration-http-address (default "0.0.0.0:80"))
  (https-address httpjet-configuration-https-address (default ""))
  (extra-arguments httpjet-configuration-extra-arguments (default '()))
  (extra-groups httpjet-configuration-extra-groups (default '()))
  (no-multishot-accept? httpjet-configuration-no-multishot-accept? (default #t)))

(define (httpjet-accounts config)
  (list (user-group (name "httpjet") (system? #t))
        (user-account (name "httpjet") (group "httpjet") (system? #t)
                      (home-directory "/var/lib/httpjet")
                      (supplementary-groups (httpjet-configuration-extra-groups config))
                      (shell (file-append shadow "/sbin/nologin")))))
(define (httpjet-privileges config)
  (list (privileged-program
         (program (file-append (httpjet-configuration-package config) "/bin/httpjet"))
         (capabilities "cap_net_bind_service=ep"))))
(define (httpjet-files config)
  `(("httpjet/conf" ,(file-append (httpjet-configuration-package config) "/share/httpjet/conf"))))
(define (httpjet-activation config)
  (let ((package (httpjet-configuration-package config)))
    #~(begin
        (use-modules (guix build utils))
        (let* ((account (getpwnam "httpjet")) (uid (passwd:uid account)) (gid (passwd:gid account)))
          (for-each (lambda (directory)
                      (mkdir-p directory) (chown directory uid gid) (chmod directory #o750))
                    '("/run/httpjet" "/var/lib/httpjet" "/var/log/httpjet"))
          (let ((state "/var/lib/httpjet-installation")
                (marker "/var/lib/httpjet-installation/declarative-initialized"))
            (when (let ((existing (false-if-exception (lstat state))))
                    (and existing (eq? (stat:type existing) 'symlink)))
              (error "httpjet installation state is a symlink"))
            (mkdir-p state) (chown state 0 0) (chmod state #o700)
            (unless (file-exists? marker)
              (unless (or (file-exists? "/var/www/httpjet")
                          (false-if-exception (lstat "/var/www/httpjet")))
                (mkdir-p "/var/www")
                (mkdir "/var/www/httpjet" #o755)
                (copy-file #$(file-append package "/share/httpjet/welcome/index.html")
                           "/var/www/httpjet/index.html"))
              (call-with-output-file marker (lambda (port) (display "initialized\n" port)))
              (chmod marker #o600)))))))
(define (httpjet-shepherd config)
  (let ((package (httpjet-configuration-package config))
        (root (httpjet-configuration-config-root config))
        (http (httpjet-configuration-http-address config))
        (https (httpjet-configuration-https-address config))
        (extra (httpjet-configuration-extra-arguments config))
        (groups (httpjet-configuration-extra-groups config))
        (no-multishot? (httpjet-configuration-no-multishot-accept? config)))
    (list
     (shepherd-service
      (documentation "Run httpjet with mandatory io_uring as the dedicated account.")
      (provision '(httpjet))
      (requirement '(user-processes networking))
      (respawn? #t)
      (respawn-delay 2)
      (modules '((shepherd service) (guix build utils) (srfi srfi-13)))
      (start
       #~(lambda _
           (let* ((account (getpwnam "httpjet"))
                  (directory (mkdtemp! (string-copy "/run/httpjet/launch-XXXXXX")))
                  (marker (string-append directory "/ready"))
                  (groups (cons (passwd:gid account)
                                (map (lambda (name) (group:gid (getgrnam name))) '#$groups))))
             (chown directory (passwd:uid account) (passwd:gid account))
             (chmod directory #o750)
             (unless
              (zero? (system* #$(file-append coreutils "/bin/env") "-i"
                              "PATH=/run/current-system/profile/bin:/run/current-system/profile/sbin"
                              "HTTPJET_LOG_DIR=/var/log/httpjet"
                              #$(file-append util-linux "/bin/setpriv")
                              (string-append "--reuid=" (number->string (passwd:uid account)))
                              (string-append "--regid=" (number->string (passwd:gid account)))
                              (string-append "--groups=" (string-join (map number->string groups) ","))
                              "--" #$(file-append package "/bin/httpjet") "--root" #$root "check" "--strict"))
              (error "httpjet configuration check failed as the service account"))
             ((make-forkexec-constructor
               (append (list "/run/privileged/bin/httpjet" "--root" #$root "serve"
                             "--http-addr" #$http (string-append "--https-addr=" #$https)
                             "--metrics-addr=" "--no-php" "--ready-file" marker)
                       (if #$no-multishot? '("--no-multishot-accept") '()) '#$extra)
               #:user "httpjet" #:group "httpjet" #:supplementary-groups groups
               #:directory "/var/lib/httpjet" #:file-creation-mask #o027
               #:pid-file marker #:pid-file-timeout 30
               #:resource-limits '((nofile 65536 65536) (memlock 8388608 8388608))
               #:environment-variables
               '("PATH=/run/current-system/profile/bin:/run/current-system/profile/sbin"
                 "HTTPJET_LOG_DIR=/var/log/httpjet" "RUST_LOG=httpjet=info")
               #:log-file "/var/log/httpjet/shepherd.log")))))
      (stop #~(make-kill-destructor SIGTERM #:grace-period 30))))))

(define httpjet-service-type
  (service-type
   (name 'httpjet)
   (extensions
    (list (service-extension account-service-type httpjet-accounts)
          (service-extension etc-service-type httpjet-files)
          (service-extension privileged-program-service-type httpjet-privileges)
          (service-extension activation-service-type httpjet-activation)
          (service-extension shepherd-root-service-type httpjet-shepherd)))
   (description "Declare httpjet, its account, immutable configuration and narrow low-port capability.")))
