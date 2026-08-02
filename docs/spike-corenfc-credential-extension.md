# Spike memo: CoreNFC inside ASCredentialProviderExtension

**Project:** PassPony — password manager with OpenPGP smartcard (YubiKey NFC / USB-C) decryption
**Date:** 2026-08-02
**Question:** Can the Password AutoFill credential provider extension (`ASCredentialProviderExtension`) run an NFC tag session (ISO 7816 APDUs to the OpenPGP applet) — or talk to a USB-C YubiKey — to decrypt an entry at fill time?

---

## Verdict

**No — CoreNFC does not work inside an ASCredentialProviderExtension, and this is confirmed by Apple engineers, not just folklore.** `NFCTagReaderSession`/`NFCNDEFReaderSession` are unavailable in all app extensions; the NFC entitlement cannot even be added to an extension target, and Apple DTS has stated flatly that there are "no tricks, workarounds, or entitlements" to make it work and that the only viable pattern is to do NFC in the containing app and share the result with the extension. The USB-C story is more nuanced: Lightning (MFi/ExternalAccessory) YubiKeys demonstrably *do* work inside AutoFill extensions (KeePassium ships this), and iOS 16+ exposes USB-C CCID smart cards via CryptoTokenKit, so a USB-C YubiKey path inside the extension is plausible but publicly unverified — it is the single most valuable thing to test on-device in week one. Plan PassPony's architecture around the standard fallback: smartcard operations happen in the main app, a time-limited derived secret is shared to the extension via app-group keychain, and the extension fills from that cache.

## Evidence

**Apple, authoritative:**

- Apple Developer Forums, ["Why is CoreNFC unavailable from App Extensions (appex)?"](https://developer.apple.com/forums/thread/804820) — asked specifically about a credential provider extension authenticating against an NFC smartcard during AutoFill (i.e., exactly PassPony's use case). Apple engineer reply: *"We cannot discuss why CoreNFC is not available from app extensions. It just isn't."* and *"There are no tricks, workaround, or entitlements to make CoreNFC work from an extension."* The engineer endorses one pattern only: *"the main app performing the NFC functions and then sharing the data with the extension is about the only way this would seem to work for your use case."*
- Apple Developer Forums, ["SSO extension and NFC tag"](https://developer.apple.com/forums/thread/769575) — Apple DTS engineer (Core Technologies): *"Unfortunately NFC cannot be accessed inside credential extensions."* The thread also confirms the entitlement angle empirically: the developer reports **the NFC entitlement was not even offered in the entitlements list for the app extension target**. Same code that works in the container app silently has no NFC access in the extension.
- CoreNFC SDK headers ([NFCTagReaderSession.h, iOS SDK mirror](https://github.com/xybp888/iOS-SDKs/blob/master/iPhoneOS13.0.sdk/System/Library/Frameworks/CoreNFC.framework/Headers/NFCTagReaderSession.h)) mark reader sessions as unavailable to extensions; only one NFC reader session may be active system-wide, and sessions require a foregrounded app.

**Real-world / vendor:**

- Strongbox KB, ["Use a YubiKey With AutoFill on iOS"](https://strongbox.reamaze.com/kb/yubikey/why-doesnt-yubikey-work-in-autofill-mode): *"Apple block NFC access in AutoFill extensions, and Yubico do not provide AutoFill extension compatible software libraries."* Their shipped workarounds are (a) **challenge-response caching** — unlock in the main app with the physical key, cache the response for a period so AutoFill works without the key; (b) **virtual hardware keys** — store the HMAC secret in software.
- KeePassium, [1.51 release notes](https://keepassium.com/blog/2024/04/keepassium-1.51/) and [YubiKey-in-AutoFill KB](https://support.keepassium.com/kb/yubikey-autofill/): the **Lightning YubiKey 5Ci works fully inside the AutoFill extension** (*"YubiKeys with a Lightning connector are fully supported in AutoFill"*) — proof that *hardware key I/O per se is not banned in extensions; specifically NFC is*. NFC keys get "App only + AutoFill workaround" (cached derived key). Their [compatibility page](https://support.keepassium.com/kb/yubikey-compatibility/) notes USB-C keys required Apple's own USB-C→Lightning adapter in their 2024 tests.
- Yubico blog, ["How to implement a CryptoTokenKit extension on iOS"](https://www.yubico.com/blog/how-to-implement-a-cryptotokenkit-extension-on-ios/): Yubico itself confirms *"a lack of NFC support in the CTK extension itself"* and routes NFC through the main app (extension → local notification → main app does NFC + PIN → result passed back via shared storage). This is Yubico's own sanctioned pattern for extension-context smartcard crypto over NFC.

## USB-C / CryptoTokenKit sub-verdict

**Nuanced: likely workable, must be spiked.** Facts on record:

- iOS/iPadOS 16+ support **CCID-compliant USB-C smart card readers and tokens** system-wide ([Apple deployment guide](https://support.apple.com/guide/deployment/use-a-smart-card-on-iphone-and-ipad-dep8b8c8927a/web), [Twocanoes on iOS 16 smart card support](https://twocanoes.com/ios-16-includes-smart-card-reader-support/)). A USB-C YubiKey plugged into an iPhone 15+ enumerates as a CCID smart card; `TKSmartCardSlotManager` is the access point, and Yubico's modern [yubikit-swift](https://github.com/Yubico/yubikit-swift) SDK (iOS 16+) exposes this as `USBSmartCardConnection` alongside `NFCSmartCardConnection`.
- An [Apple DTS thread on mTLS with a USB-C YubiKey](https://developer.apple.com/forums/thread/821896) confirms the built-in **PIV** token driver picks up USB-C YubiKeys automatically, and that token-backed keys are reachable via the keychain (`kSecAttrAccessGroupToken`, `com.apple.token` keychain access group + `com.apple.security.smartcard` entitlement) — a cross-process mechanism that, unlike CoreNFC, is not an in-process reader session and is therefore plausibly reachable from an extension. Caveat for PassPony: the built-in driver speaks **PIV, not the OpenPGP applet**, so it doesn't help directly unless PassPony (a) provisions a decryption key in the PIV applet instead of/alongside OpenPGP, or (b) ships its own CryptoTokenKit smart-card token extension that speaks OpenPGP APDUs and surfaces the key through the keychain. [Twocanoes demonstrated exactly this composition](https://twocanoes.com/autofill-with-rfid-card-on-ios/) — a custom CTK extension + an AutoFill credential provider working together on iOS 16.
- **Unknown (nowhere publicly confirmed):** whether `TKSmartCardSlotManager`/`USBSmartCardConnection` returns slots when called *from inside* an `ASCredentialProviderExtension`, and whether keychain crypto against a CTK token (built-in PIV or custom) succeeds from the extension process on iOS (vs. macOS, where it clearly does). KeePassium's proven Lightning-in-AutoFill support runs over ExternalAccessory (MFi), a different stack that doesn't exist on USB-C iPhones. This is spike item #1.

Practical implication: **the PIV applet, not OpenPGP, may be the pragmatic wired path** — RSA/ECC decrypt via built-in PIV token through plain `SecKeyCreateDecryptedData`, zero custom driver code. Worth prototyping both.

## Fallback design (NFC, and until USB-C is proven): main-app roundtrip with cached vault key

Key design decision first: **do not encrypt each entry directly to the card.** If every entry needs a card tap, AutoFill is unusable. Instead: the vault (or a per-vault content key) is encrypted to the card's OpenPGP decryption key; the card decrypts the **vault key once**, in the main app; the vault key is cached, time-boxed, in shared keychain; the extension uses it to decrypt entries locally. This is exactly the Strongbox/KeePassium-proven model.

One hard constraint to design around: **the extension cannot programmatically open the main app.** `UIApplication.shared` is unavailable in extensions, `extensionContext.open(_:)` is documented to work only for a small set of extension points (effectively Today widgets) and silently no-ops in credential providers, and Apple confirmed "extensions cannot launch the main app" in the CoreNFC thread. Responder-chain `openURL:` hacks are private-API risk. The user must switch apps themselves; the extension's job is to make that one obvious tap of explanation.

Numbered flow, tap-to-fill:

1. **User focuses a login field** in Safari/app → iOS QuickType bar shows PassPony suggestions (the extension keeps `ASCredentialIdentityStore` populated with identities — metadata only, no secrets).
2. **User taps a credential.** iOS calls `provideCredentialWithoutUserInteraction(for:)` in the extension.
3. **Extension checks the app-group keychain** (access group shared with the main app, items stored `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`) for a valid cached vault key: present + not expired (e.g., 8h TTL, policy-configurable) → decrypt the entry in-process, call `extensionContext.completeRequest(withSelectedCredential:)`. Password fills instantly. **This is the 95% path.**
4. **Cache miss/expired:** extension calls `extensionContext.cancelRequest(withError: ASExtensionError(.userInteractionRequired))`. iOS then re-invokes the extension *with UI* via `prepareInterfaceToProvideCredential(for:)`.
5. **Extension shows its unlock screen.** If a software-fallback unlock exists (passphrase-wrapped backup of the vault key — recommended, opt-in), the user can unlock right here and the extension completes the request normally. Otherwise the screen says: **"Your vault key is locked. Open PassPony and tap your YubiKey, then come back and try again."** with a single "Done" button that calls `cancelRequest(withError: .userCanceled)`. (Optionally fire a local notification "Unlock PassPony vault" — tapping a notification *is* allowed to launch the main app; this is Yubico's own pattern.)
6. **User switches to the PassPony main app** (via the notification or app switcher). Main app runs `NFCTagReaderSession` (ISO 7816, OpenPGP AID `D2 76 00 01 24 01`), user enters card PIN, taps YubiKey; card runs `PSO:DECIPHER` on the wrapped vault key. Main app writes the vault key to the shared keychain with expiry metadata in the app-group `UserDefaults` (or alongside the item). Post a Darwin notification (`CFNotificationCenterGetDarwinNotifyCenter`) for freshness — note the extension is usually already dead by now, so the notification is a nicety, not the transport; **the shared keychain is the source of truth.**
7. **User returns to the target app** (app switcher / back-swipe) and taps the field → QuickType suggestion again. This time step 3 hits the cache and fills immediately. iOS does *not* resume the cancelled request — the roundtrip always costs the user one re-invocation; there is no way to complete the original request after leaving the extension.

**What the user experiences:** first fill of the day = tap credential → "unlock in PassPony" screen → open app, tap key, enter PIN → back to browser, tap credential again → filled. Every subsequent fill within TTL = instant. This matches shipping behavior in Strongbox and KeePassium, so it's an accepted UX pattern in this product category.

**Shared state inventory:** app-group keychain: cached vault key (ThisDeviceOnly, TTL-stamped), credential DB (or its file in the app-group container), settings; app-group UserDefaults: cache-expiry policy, non-secret flags; never in UserDefaults: any key material. `ASCredentialIdentityStore`: usernames/URLs only.

## Open items for the P3 week-one on-device spike

**Status (2026-08-02):** the spike checks ship inside the autofill extension
("Spike" screen in the picker). Item 1 is **deferred to the tester pool** —
no USB-capable iPhone/YubiKey combination in-house; the KDF YubiKey tester
runs the checks from the first TestFlight build and reports a screenshot.
This defers an *optimization*, not a dependency: the cached-vault-key
fallback below is the design of record and works either way.

1. **USB-C YubiKey inside the AutoFill extension (the big one):** on an iPhone 15+/17, from a minimal `ASCredentialProviderViewController`, (a) enumerate `TKSmartCardSlotManager.default?.slotNames` with a USB-C YubiKey inserted; (b) try yubikit-swift `USBSmartCardConnection` + a raw SELECT of the OpenPGP AID; (c) with a PIV-provisioned key, try `SecItemCopyMatching(kSecAttrAccessGroupToken)` + `SecKeyCreateDecryptedData` from the extension process (needs `com.apple.security.smartcard` + `com.apple.token` keychain group — confirm those entitlements are grantable on an extension target, and note they require a paid/org team, not a Personal Team).
2. **Confirm NFC entitlement behavior in current Xcode:** verify `com.apple.developer.nfc.readersession.formats` still cannot be attached to the extension target / that `NFCTagReaderSession.readingAvailable` is false in-extension on current iOS (expected: yes, still blocked — but the memo's verdict rests on this, so burn 30 minutes confirming).
3. **`extensionContext.open(_:)` from the credential provider:** confirm it no-ops on current iOS (decides whether the "open PassPony" button can deep-link or must be instructions + notification).
4. **Local notification from the extension:** confirm `UNUserNotificationCenter` works from the AutoFill extension process and that tapping the notification cold-launches the main app into the NFC flow.
5. **Shared keychain latency/coherence:** write vault key in main app, immediately re-invoke AutoFill — confirm the extension sees the fresh item (no stale keychain cache), and measure step-3 fill latency.
6. **Cache TTL enforcement:** verify `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` + our own expiry check behaves across device lock/reboot; decide whether to add `LAContext`/biometric gating on the cached key read in the extension.
7. **Memory ceiling:** AutoFill extensions have a low jetsam limit (~tens of MB); confirm OpenPGP decrypt + vault parse fits.

## Sources

- https://developer.apple.com/forums/thread/804820 — Apple DTS: CoreNFC unavailable in extensions, no workarounds, main-app pattern endorsed
- https://developer.apple.com/forums/thread/769575 — Apple DTS: "NFC cannot be accessed inside credential extensions"; NFC entitlement not offered on extension targets
- https://github.com/xybp888/iOS-SDKs/blob/master/iPhoneOS13.0.sdk/System/Library/Frameworks/CoreNFC.framework/Headers/NFCTagReaderSession.h — SDK header availability annotations
- https://strongbox.reamaze.com/kb/yubikey/why-doesnt-yubikey-work-in-autofill-mode — Strongbox: NFC blocked in AutoFill; caching + virtual key workarounds
- https://keepassium.com/blog/2024/04/keepassium-1.51/ — KeePassium: YubiKey 5Ci (Lightning) fully working inside AutoFill
- https://support.keepassium.com/kb/yubikey-autofill/ — KeePassium cached-derived-key AutoFill workaround
- https://support.keepassium.com/kb/yubikey-compatibility/ — KeePassium compatibility matrix (NFC = app only; USB-C via Apple adapter)
- https://www.yubico.com/blog/how-to-implement-a-cryptotokenkit-extension-on-ios/ — Yubico: no NFC in CTK extension; notification → main app → shared storage pattern
- https://developer.apple.com/forums/thread/821896 — Apple DTS: built-in PIV token over USB-C, `com.apple.token` keychain group, required entitlements
- https://support.apple.com/guide/deployment/use-a-smart-card-on-iphone-and-ipad-dep8b8c8927a/web — Apple: USB-C CCID smart card support on iPhone/iPad (iOS 16+)
- https://twocanoes.com/ios-16-includes-smart-card-reader-support/ and https://twocanoes.com/autofill-with-rfid-card-on-ios/ — iOS 16 smart card reader support; CTK extension + AutoFill credential provider proof of concept
- https://github.com/Yubico/yubikit-swift — YubiKit Swift SDK: NFC/Lightning/USB-C connections, iOS 16+
- https://github.com/keepassium/KeePassium/releases — KeePassium release history (YubiKit device recognition updates)
- https://developer.apple.com/forums/thread/762458 — unanswered thread on openURL from an AutoFill credential provider (illustrates the gap; no sanctioned API)
- https://developer.apple.com/documentation/AuthenticationServices/ASCredentialProviderViewController — extension lifecycle: `provideCredentialWithoutUserInteraction`, `prepareInterfaceToProvideCredential`, `ASExtensionError.userInteractionRequired`
