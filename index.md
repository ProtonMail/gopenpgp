---
layout: default
title: GopenPGP
description: An easy-to-use OpenPGP wrapper library written in golang
---

# What is GopenPGP?

GopenPGP is a high-level OpenPGP wrapper library developed by Proton Mail, as well as a fork of the golang crypto library, which the wrapper library is built on. The goal of this project is to provide an easy-to-use, open source encryption wrapper library for the developer community that is well-maintained, up-to-date with the latest OpenPGP RFC changes, and periodically audited for security. 

# Updates

We are currently in discussions with the maintainers of the [original golang crypto library](https://github.com/golang/crypto/) to include our improvements there. In the meantime, we wanted to open source our modifications. Among our improvements, we have:

- Added support for elliptic curve cryptography
- Undergone an audit by [SEC Consult](/assets/Source_Code_Review_-_Proton_Crypto_Library.pdf)
- Fixed a number of security issues, including:
  - Rejecting packets that are not integrity-protected (those exploited by Efail)
  - Preventing potential spoofing in cleartext message headers
  - Increasing the default key-derivation (S2K) cost parameters
- Added a high-level wrapper library, which provides a simple API for common operations such as key generation, encryption, decryption, signing, and verification, and which is compatible with go-mobile

# Contribute to GopenPGP

We welcome contributions and feedback from the community. We will continuously improve the libraries to better our documentation and API, while fixing bugs and building out new features. We invite feedback and contributions, as well as security issues, at [https://github.com/ProtonMail/gopenpgp](https://github.com/ProtonMail/gopenpgp) and [https://github.com/ProtonMail/go-crypto](https://github.com/ProtonMail/go-crypto).

# Supporters

<a class="card text-center" href="https://proton.me/mail" title="Proton Mail" target="_blank">
  <img id="logo-proton-mail" alt="Proton Mail logo" title="Proton Mail" src="/assets/img/logo-proton-mail-white.svg">
  <small>Proton Mail</small>
</a>
<a class="card text-center" href="https://ec.europa.eu/programmes/horizon2020/en" title="Horizon 2020" target="_blank">
  <img id="logo-eu" alt="Horizon2020 logo" title="This project is supported by the Horizon 2020 Framework Programme of the European Union" src="/assets/img/logo-gdpr-eu-white.svg">
  <small>Horizon 2020</small>
</a>
