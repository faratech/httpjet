(use-modules (guix channels))
(list (channel
       (name 'guix)
       (url "https://git.guix.gnu.org/guix.git")
       (commit "ae27c30d2900d30af80abc99c6deb4ec5c2be87f")
       (introduction
        (make-channel-introduction
         "9edb3f66fd807b096b48283debdcddccfea34bad"
         (openpgp-fingerprint "BBB0 2DDF 2CEA F6A8 0D1D E643 A2A0 6DF2 A33A 54FA")))))
