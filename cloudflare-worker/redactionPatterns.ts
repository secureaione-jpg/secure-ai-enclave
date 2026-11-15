/**
 * What a structured identifier looks like.
 *
 * Every pattern the structured stage scans with, and nothing that decides
 * what to do with a match: the shapes live here, the checksums and the
 * stand-ins live in redactionStructured, which is the only caller. Split out
 * because the two read at different speeds — a regex is checked character by
 * character against the comment above it, and the code around it was scrolled
 * past to get there.
 *
 * Every pattern here is deliberately narrow. The failure that matters is not a
 * missed number, it is a mangled answer — a version string read as a phone
 * number, an order id read as a card — because the user then sees the model
 * reason confidently about a value they never wrote. Cards are Luhn-checked
 * rather than length-checked for exactly that reason.
 */

/** A local part, an @, a domain with a real TLD. */
/* Unicode letters, not just ASCII ones. An address with an accent in the local
   part or a non-ASCII domain — józef@münchen.de — is an ordinary address in
   most of the world and was invisible to an A-Za-z pattern, which is the same
   failure the digit normalisation above fixes, in the other half of the
   character set. */
/*
 * The lookbehind and the length cap are both about cost, not correctness.
 *
 * Without them this pattern is quadratic on any long run of letters or digits.
 * The local part happily matches the whole run, fails to find an "@", gives
 * back one character and tries again — and then the engine advances one
 * position and does it all over. Pasting thirty thousand digits into a message
 * took 620ms of Worker CPU on the path every message goes through, which is a
 * way for one message to spend the request's whole budget.
 *
 * The lookbehind means only the first character of a run can begin a match, so
 * there is one scan rather than one per position. The cap is the length RFC
 * 5321 gives a local part, so it costs nothing real and bounds the work.
 */
/**
 * An API key, an access token, or anything else long and secret.
 *
 * This existed on the devices and not here, which is the wrong way round for
 * an agent: the apps carry it in clientRules and get it over /config, while
 * /v1/redact, /v1/inspect, the gateway and MCP — the surfaces an agent
 * actually calls — ran every other pattern and not this one. A tool payload
 * is where a secret is most likely to be, and a leaked key is the finding
 * with the shortest path from "sent" to "somebody else is paying for this".
 *
 * The kind is "secret", which policy.ts and vocabulary.ts already named and
 * had no producer for — the union anticipated this and nothing filled it.
 *
 * Prefixes rather than entropy. A high-entropy-string heuristic finds every
 * base64 blob in a document — an image, a signature, a session id — and a
 * redaction engine that eats attachments is one nobody leaves switched on.
 * Each branch below is a vendor's published prefix, so a match is a statement
 * about what the string is rather than about how random it looks:
 *
 *   AIza…            Google
 *   AKIA…            AWS access key id
 *   ghp_ gho_ ghu_   GitHub, and its other four
 *   github_pat_      GitHub fine-grained tokens
 *   glpat-           GitLab
 *   npm_ hf_ SG.     npm, Hugging Face, SendGrid
 *   shpat_ pypi-     Shopify, PyPI
 *   dop_v1_          DigitalOcean
 *   ZXlK…            a JWT that has been base64-encoded again
 *   A3- sntrys_ sha256~ ABSK p8e- v1.0- fm1_ s-s4t2  1Password, Sentry,
 *                    OpenShift, Bedrock, Adobe, Cloudflare Origin CA, Fly.io,
 *                    Intra42 — all from gitleaks' rules
 *   M….….…           a Discord bot token; 123456789:AA… a Telegram one;
 *                    GR1348941… a GitLab runner registration token
 *   glcbt- gldt- …   the rest of GitLab's family, and the other distinctive
 *                    prefixes in gitleaks' rules (MIT): Databricks, Fly.io,
 *                    Doppler, Dynatrace, age, Flutterwave, EasyPost, Clojars,
 *                    Artifactory, Duffel, 1Password service accounts
 *   hooks.slack.com  a Slack or Discord webhook URL: the URL is the credential
 *   xoxb- xoxp- …    Slack
 *   sk-  sk-proj-    OpenAI, including the project form
 *   sk-ant-          Anthropic
 *   sai_             ours, which was also going through in the clear
 *   sk_live_ pk_…    Stripe and the several that copied its shape
 *   eyJ….….…         a JWT
 *
 * `sk-[0-9A-Za-z]{20,}` was the clients' expression and it misses
 * sk-proj-… , because the run after "sk-" cannot contain a hyphen. Hyphens
 * and underscores are allowed inside the tail here, which is what a modern
 * OpenAI key actually looks like.
 */
export const SECRET_PATTERN =
  /\b(?:AIza[0-9A-Za-z_-]{30,35}|(?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}|gh[pousr]_[0-9A-Za-z]{20,}|(?:live|test)_(?=[0-9A-Za-z]*\d)(?=[0-9A-Za-z]*[A-Z])[0-9A-Za-z]{20,40}|github_pat_[0-9A-Za-z_]{22,}|glpat-[0-9A-Za-z_-]{20,}|npm_[0-9A-Za-z]{36}|ZXlK[0-9A-Za-z+/]{40,}={0,2}|A3-[0-9A-Z]{6}-(?:[0-9A-Z]{11}|[0-9A-Z]{6}-[0-9A-Z]{5})-[0-9A-Z]{5}-[0-9A-Z]{5}-[0-9A-Z]{5}|sntry[su]_[0-9A-Za-z+/=_-]{50,}|sha256~[0-9A-Za-z_-]{40,50}|s-s4t2(?:ud|af)-[0-9a-f]{64}|ABSK[0-9A-Za-z+/]{100,}={0,2}|p8e-[0-9a-f]{32}|v1\.0-[0-9a-f]{24}-[0-9a-f]{146}|fm[12][ar]?_[0-9A-Za-z+/=_-]{100,}|[MNOA][0-9A-Za-z_-]{23,25}\.[0-9A-Za-z_-]{6}\.[0-9A-Za-z_-]{27,}|\d{8,10}:AA[0-9A-Za-z_-]{32,33}|GR1348941[0-9A-Za-z_-]{20,}|sgp_[0-9A-Za-z_]{40,}|ntn_[0-9A-Za-z]{40,}|hvs\.[0-9A-Za-z_-]{90,}|xapp-\d-[0-9A-Z]+-\d+-[0-9a-f]{40,}|gl(?:sa|c)_[0-9A-Za-z_]{30,}|NR(?:AK|JS|II)-[0-9A-Za-z]{19,32}|pnu_[0-9A-Za-z]{36}|pul-[0-9a-f]{40}|rdme_[0-9a-z]{70}|api_org_[0-9A-Za-z]{34}|EAA[0-9A-Za-z]{100,}|\d{15,16}\|[0-9A-Za-z_-]{27}|(?:https:\/\/)?[0-9a-z-]{1,63}\.webhook\.office\.com\/webhookb2\/[0-9a-z@-]{30,}(?:\/IncomingWebhook\/[0-9a-z]+\/[0-9a-z-]+)?|gl(?:cbt|dt|ffct|ft|imt|agent|oas|ptt|rt|soat)-[0-9A-Za-z_-]{16,}|dapi[0-9a-f]{32}|do[opr]_v1_[0-9a-f]{64}|fo1_[0-9A-Za-z_-]{30,}|dp\.(?:pt|st|sa|ct|scim|audit)\.[0-9A-Za-z]{40,}|dt0c01\.[0-9A-Z]{24}\.[0-9A-Z]{64}|AGE-SECRET-KEY-1[0-9A-Z]{58}|FLW(?:SECK|PUBK)_TEST-[0-9a-f]{12,32}(?:-X)?|EZ[AT]K[0-9A-Za-z]{54}|CLOJARS_[0-9a-z]{60}|AKCp[0-9A-Za-z]{69}|duffel_(?:test|live)_[0-9A-Za-z_=-]{43}|ops_eyJ[0-9A-Za-z+/=]{200,}|hf_[0-9A-Za-z]{30,}|SG\.[0-9A-Za-z_-]{16,}\.[0-9A-Za-z_-]{16,}|shp(?:at|ss|ca|pa)_[0-9a-fA-F]{32}|pypi-[0-9A-Za-z_-]{50,}|dop_v1_[0-9a-f]{64}|(?:https?:\/\/)?hooks\.slack\.com\/(?:services|workflows|triggers)\/(?:[0-9A-Za-z]+\/[0-9A-Za-z]+\/[0-9A-Za-z]+|[0-9A-Za-z+\/]{43,56})|https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[0-9A-Za-z_-]+|xox[abeprs]-[0-9A-Za-z-]{10,}|sk-ant-[0-9A-Za-z_-]{20,}|sk-(?:proj-)?[0-9A-Za-z_-]{20,}|sai_(?:live|test)_[0-9A-Za-z]{16,}|(?:sk|pk|rk)_(?:live|test)_[0-9A-Za-z]{16,}|eyJ[0-9A-Za-z_-]{10,}\.(?:[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}|eyJ[0-9A-Za-z_-]{10,}))\b/gd;

/**
 * More vendor prefixes, kept apart from SECRET_PATTERN so that line stays
 * readable. Each is the vendor's documented shape, the same ones gitleaks
 * ships rules for: Twilio API keys (SK + 32 hex), Mailgun (key-), Mailchimp
 * (32 hex, -us and a datacentre), Square, Postman, Linear, Airtable personal
 * tokens, Heroku (HRKU-), Supabase (sbp_), Mapbox secret tokens (sk.eyJ),
 * Alibaba (LTAI), Tencent (AKID), Bitbucket (ATBB), Atlassian (ATATT3), Figma
 * (figd_), Brevo (xkeysib-/xsmtpsib-), Terraform Cloud (.atlasv1.),
 * PlanetScale, Replicate (r8_), Groq (gsk_), Perplexity (pplx-), Contentful
 * (CFPAT-), Adafruit (aio_), Shippo, Plaid access tokens, Dropbox (sl.) and
 * Typeform (tfp_).
 */
export const SECRET_VENDOR_PATTERN =
  /\b(?:SK[0-9a-f]{32}|key-[0-9a-z]{32}|[0-9a-f]{32}-us\d{1,2}|sq0(?:atp|csp)-[0-9A-Za-z_-]{22,43}|PMAK-[0-9a-f]{24}-[0-9a-f]{34}|lin_api_[0-9A-Za-z]{40}|pat[0-9A-Za-z]{14}\.[0-9a-f]{64}|HRKU-[0-9A-Za-z_-]{40,64}|sbp_[0-9a-f]{40}|(?:sk|tk)\.eyJ[0-9A-Za-z_-]{20,400}\.[0-9A-Za-z_-]{20,100}|LTAI[0-9A-Za-z]{12,20}|AKID[0-9A-Za-z]{32}|ATBB[0-9A-Za-z]{32,64}|ATATT3[0-9A-Za-z_=-]{60,300}|figd_[0-9A-Za-z_-]{40,64}|x(?:keysib|smtpsib)-[0-9a-f]{64}-[0-9A-Za-z]{16}|[0-9A-Za-z]{14}\.atlasv1\.[0-9A-Za-z_=-]{60,70}|pscale_(?:tkn|pw|oauth)_[0-9A-Za-z_.-]{32,64}|r8_[0-9A-Za-z]{37}|gsk_[0-9A-Za-z]{52}|pplx-[0-9A-Za-z]{48}|CFPAT-[0-9A-Za-z_-]{43}|aio_[0-9A-Za-z]{28}|shippo_(?:live|test)_[0-9a-f]{40}|access-(?:production|sandbox|development)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|sl\.(?:u\.)?[0-9A-Za-z_-]{130,1500}|tfp_[0-9A-Za-z_-]{40,80})(?![\w-])/gd;

/**
 * The key inside an Azure connection string (`AccountKey=…`,
 * `SharedAccessKey=…`), and the signature on a signed URL: an Azure SAS
 * `sig=`, an S3 presigned `X-Amz-Signature=`, a Google `Signature=`. The
 * rest of the URL stays; the signature is what lets anyone read the file.
 */
export const SIGNED_KEY_PATTERN =
  /\b(?:AccountKey|SharedAccessKey)=([0-9A-Za-z+\/]{40,90}={0,2})|[?&](?:sig|X-Amz-Signature|X-Goog-Signature|Signature)=([0-9A-Za-z%+\/_-]{30,1024})/gd;

/**
 * A secret with no vendor prefix, found by the label in front of it:
 * `password: hunter2`, `"api_key": "…"`, `client_secret=…`.
 *
 * Group 1 is the value; the label stays so the model still knows what it is
 * looking at. The separator has to be `:` or `=` — "password reset emails go
 * out daily" is a sentence. What follows must look like a credential rather
 * than prose, which findStructured checks (see plausibleAssignedSecret):
 * "password: please ask Dave" is somebody declining to share one.
 *
 * The label may also end an environment variable's name — `JWT_SECRET=`,
 * `SMTP_PASSWORD=` — which is where most of them live in a .env file.
 *
 * The value has to end where it ends: at a quote, a space, a separator or a
 * sentence's full stop. `api_key="sai_..."` is documentation showing where a
 * key goes, and taking "sai_" out of it would protect nothing.
 */
export const ASSIGNED_SECRET_PATTERN =
  /(?:\b|(?<=[A-Za-z0-9]_))(?:password|passwd|pwd|passcode|secrete?|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|refresh[_-]?token|client[_-]?secret|(?:aws[_-]?)?secret[_-]?access[_-]?key|secret[_-]?key|private[_-]?key|db[_-]?pass|(?<=[A-Za-z0-9]_|[{,][ \t]{0,3}|["'])pass)(?:[_-][a-z]+){0,3}\b(?:\[\d*\])?["']?(?:[ \t]*(?:[!=]==?|:=|=>|[:=])\s*@?|(?<=pass(?:wor)?d)\s+(?="))(?:"([^"\n]{4,2048})"|'([^'\n]{4,2048})'|`([^`\n]{4,2048})`|([^\s"'`,;]{3,2047}[^\s"'`,;}.])(?=[\s"'`,;}]|\.(?:\s|$)|$))/gid;

/**
 * The same secret written the other way round, or handed to a constructor:
 * `if ("…" == password)`, `std::string secret("…")`, `secret.assign("…")`.
 * Only a quoted value, so the quotes say where it starts and ends.
 */
export const SECRET_COMPARED_PATTERN =
  /"([^"\n]{4,128})"\s*[!=]==?\s*(?:[a-z]+_)*(?:password|passwd|pwd|secrete?|api[_-]?key|apikey|private[_-]?key|db[_-]?pass)(?:_[a-z]+)?\b|\b(?:secrete?|password|passwd|api[_-]?key|private[_-]?key)(?:\.assign)?\(\s*"([^"\n]{4,128})"/gid;

/**
 * A secret assigned to a variable whose name says what it is:
 * `adobeToken = "…"`, `databricks_TOKEN := "…"`, `var algoliaToken string = "…"`,
 * `<gocardlessToken>…</gocardlessToken>`, `"ClickHouse_token": "…"`.
 *
 * ASSIGNED_SECRET_PATTERN knows a fixed list of labels. Code names its
 * secrets after the vendor, and gitleaks' own test keys (MIT, 5,963 of them
 * across 215 rules) were 86% missed until this existed. The name must END in
 * the word — `adobeToken`, `X_SECRET`, `api-key` — as a whole part of it:
 * after a separator, after a lower-case letter in camelCase, or alone.
 * "monkey" does not end in a part called key.
 *
 * The value is checked in findStructured (plausibleNamedSecret): it has to
 * look generated, because `sortKey = "createdAt"` is configuration.
 */
/**
 * The inside of a credentials tag: Jenkins stores every saved secret as
 * `<secret>{AQAAABAAA…}</secret>`, and config files write `<password>`,
 * `<apiKey>` and `<token>` the same way. The tag says what it holds.
 */
export const XML_SECRET_TAG_PATTERN =
  /<(secret|password|passwd|apiKey|api_key|apikey|token|accessToken|access_token|privateKey|private_key|clientSecret|client_secret)>[ \t]*\{?([^<>{}\n]{8,512}?)\}?[ \t]*<\/\1>/gd;

/**
 * "Key=" on its own, in a log line or a query string, and "key is" in a
 * sentence: "[DEBUG] Using Key=oxpf4a93…", "?key=6b1c…", "Your API2CART key
 * is 5d2f…". The value still has to look generated (plausibleNamedSecret),
 * so "key=createdAt" and "the key is required" are left.
 */
export const BARE_KEY_PATTERN =
  /(?<![\w-])(?:[Kk]ey|KEY|Token|Secret)(?:[ \t]*=[ \t]*|[ \t]+is[ \t]+)["'`]?([A-Za-z0-9_\-.+\/]{16,256}=*)(?=["'`]?(?:[\s&#,;.)}\]]|$))/gd;

/**
 * "key:" and "token" with a generated value after them and no "=": "ScrapingBee
 * API key: QEUXIXLN8OULIISPZ1FX…", "[DEBUG] Using token spu-3f10194c…". No
 * dots or colons in the value, so "key: kubernetes.io/hostname" and "token:
 * abcdef.0123456789abcdef" are configuration; findStructured also wants a
 * digit and a letter in it, so "the token expired" is a sentence.
 */
export const KEY_SPOKEN_PATTERN =
  /(?<![\w-])(?:[Kk]ey|KEY|[Tt]oken|TOKEN)(?:[ \t]*:[ \t]*["'`]?|[ \t]+)([A-Za-z0-9_\-+\/]{20,256}=*)(?=["'`]?(?:[\s,;)}\]]|$))/gd;

export const NAMED_SECRET_PATTERN =
  /(?<![\w.-])(?:[a-z]{4,}(?:accountkey|apikey|accesskey|secretkey|authtoken|accesstoken|apitoken|apisecret|clientsecret)|_?[A-Za-z0-9]+(?:[_.-]+[A-Za-z0-9]+)*[_.-](?:token|secret|key|password|passwd|pwd|credentials?|TOKEN|SECRET|KEY|PASSWORD|PASSWD|PWD|CREDENTIALS?|Token|Secret|Key|Password)|_?[A-Za-z][A-Za-z0-9_.-]*[A-Za-z0-9](?:Token|Secret|Key|Password|Passwd|Credentials?)|token|secret|TOKEN|SECRET)(?:[_-]?\d{1,3})?["']?(?:\s+(?:string|String|str|const))?\s*(?:[:?.+]{0,3}=|=>|:|>|,(?=\s*["'])|(?<!\n[ \t]*)-(?=[ \t]*["'`]))\s*["'`]?([^\s"'`,;}<]{8,4096})(?=[\s"'`,;}<]|$)/gd;

/** An Authorization header carrying a bare token, with no Bearer or Basic in
 *  front: `Authorization: 5eb4223e-5008-46e5-…`. */
export const AUTH_HEADER_BARE_PATTERN =
  /\bAuthorization["']?\s*:\s*["']?(?!Bearer\b|Basic\b|Token\b)([A-Za-z0-9._~+\/-]{16,}=*)/gdi;

/** An Azure AD client secret: three characters, a digit, "Q~", then 31 to 34
 *  more. The "~" means it cannot start at a word boundary, so it is its own
 *  pattern rather than a branch of SECRET_PATTERN. */
export const AZURE_CLIENT_SECRET_PATTERN = /(?<![\w~.-])[\w~.]{3}\dQ~[\w~.-]{31,34}(?![\w~.-])/g;

/** `curl -u elastic:P@ssw0rd$1` — the password half of a basic-auth pair on
 *  a command line. The user name stays. */
export const CURL_USER_PATTERN = /(?:\s-u|--user)\s+["']?[^\s:"']*:([^\s"']{4,128})/gd;

/**
 * "The password is MyP@ssw0rd!" — a password introduced by "is" rather than
 * a colon. Prose uses the same words ("the password is required"), so the
 * value must carry a digit or a symbol; findStructured checks that.
 */
export const PASSWORD_IS_PATTERN =
  /\b(?:password|passcode|passphrase|passwd)\s+(?:is|was)\s*:?\s+["'“]?([^\s"'”]{3,63}[^\s"'”.,;:)])/gid;

/**
 * A password a few words after the word for one, in the forty languages:
 * "Moje heslo Pejsek2026!", "la régi Muskatli62! volt", "het oude was
 * Tulp2026!!", "Мій пароль Sonce2025#", "密碼我設成Mimi0612!!", "كلمة المرور
 * هذي قوية كفاية لحساب البنك؟ Nour#7781xq" (realistic5). The words between are
 * anything up to sixty characters, so findStructured holds the value to a
 * password's shape: letters, digits and a symbol.
 */
const PASSWORD_WORD = String.raw`(?:password\p{L}*|passwort|kennwort|passcode|passord(?:et)?|contrase[ñn]a|contrasenya|senha|parola|wachtwoord|l[öo]senord(?:et)?|adgangskode|kodeord|koden|salasana(?:n)?|heslo|has[łl]o|jelsz[óo]|jelszav\p{L}*|[şs]ifre\p{L}*|parol\p{L}*|lozink\p{L}*|geslo|κωδικ\p{L}*|пароль|пароля|паролем|סיסמ[הא]|पासवर्ड|পাসওয়ার্ড|كلمة[ \t]+(?:المرور|السر)|پاس[ \t]?ورڈ|密碼|密码|パスワード|비밀번호|รหัสผ่าน|m[ậa]t[ \t]+kh[ẩa]u|kata[ \t]+sandi|kata[ \t]?laluan)`;
// What a password is written in: Latin, Cyrillic or Greek letters, digits and
// the keyboard's symbols, so "密碼我設成Mimi0612!!但" gives the password alone.
const PASSWORD_CHAR = String.raw`[\p{Script=Latin}\p{Script=Cyrillic}\p{Script=Greek}\p{N}!#$%&*+=?@^_~.-]`;
export const PASSWORD_WORLD_NEAR_PATTERN = new RegExp(
  String.raw`(?<![\p{Script=Latin}\p{Script=Cyrillic}\p{Script=Greek}])${PASSWORD_WORD}(?![\p{Script=Latin}\p{Script=Cyrillic}\p{Script=Greek}])[^\n]{0,60}?(?<![\p{Script=Latin}\p{Script=Cyrillic}\p{Script=Greek}\p{N}_@#$!%&*.-])((?=${PASSWORD_CHAR}*\p{L})(?=${PASSWORD_CHAR}*\d)${PASSWORD_CHAR}{5,39}[\p{Script=Latin}\p{Script=Cyrillic}\p{Script=Greek}\p{N}!#$%&*+=?@^_~-])(?![\p{Script=Latin}\p{Script=Cyrillic}\p{Script=Greek}\p{N}!#$%&*+=?@^_~-]|\.+[\p{L}\p{N}])`,
  "giud",
);

/** A door or gate code under its label: "code porte 4821B", "la clave del
 *  portón es 7392#", "portkod 1234". */
export const DOOR_CODE_PATTERN =
  /(?:\bcode[ \t]+(?:porte|portail|d['’]entr[ée]e|de[ \t]+la[ \t]+porte)|\bclave[ \t]+del[ \t]+port[óo]n|\bc[óo]digo[ \t]+del[ \t]+port[óo]n|\bportkod(?:en)?|\bd[øo]rkode(?:n)?|\bt[üu]rcode|\bcodice[ \t]+(?:del[ \t]+)?portone|\bdoor[ \t]+code|\bgate[ \t]+code)[ \t]*(?:es|est|is|ist|è|er|är|:)?[ \t]*([0-9A-Z#*]{4,8})(?![0-9A-Za-z#*])/gid;

/**
 * The same with what the password is for in between — "the password for the
 * patient portal is Rainbow@2025", "the password to the server was …" — or
 * set off by a comma: "requires a password, Sarah1995." Gretel's PII test
 * set (2026-10-05) wrote 20 of its 30 passwords these ways and the engine
 * took 10. Four words at most in between; the value is judged as above.
 * Also where it is, rather than what it is for: "our wifi password at the
 * office is …", "the password in the safe was …".
 */
export const PASSWORD_FOR_PATTERN =
  /\b(?:password|passcode|passphrase|passwd)(?:\s+(?:for|to|of|on|at|in)\s+(?:[\w-]{1,30}\s+){0,4}?(?:is|was)|\s*,)\s+["'“]?([^\s"'”]{3,63}[^\s"'”.,;:)])/gid;

/**
 * The credential in an HTTP Authorization header: `Bearer abc123…`,
 * `Basic dGhpc2…`. "The Bearer token scheme" is prose, and the length floor
 * and the digit findStructured requires are what keep it that way.
 */
export const AUTH_HEADER_PATTERN = /\b(?:Bearer|Basic)\s+([A-Za-z0-9._~+\/-]{16,}=*)/gd;

/**
 * The password inside a connection string or URL:
 * `postgres://admin:S3cretPass@db.internal:5432/prod`. Only group 1, the
 * password, is taken; the user name and host stay readable. Scanned before
 * email, which would otherwise claim `S3cretPass@db.internal` and leave the
 * "admin:" half of it to explain what it was.
 *
 * Every run is bounded: an unbounded scheme is re-read from every word
 * boundary in a long hyphenated host, which scanner-safety times.
 */
export const URL_CREDENTIAL_PATTERN =
  /\b[a-z][a-z0-9+.-]{0,15}:\/\/[^\s:@\/"']{1,64}:([^\s@\/"';]{1,128})@/gid;

/**
 * A PEM private key. The body runs over several lines, and a value with a
 * newline in it cannot be substituted (isSubstitutable), so findStructured
 * takes each line of the body as its own secret. The BEGIN and END lines are
 * labels, not key material, and stay.
 */
export const PEM_PRIVATE_KEY_PATTERN =
  /-----BEGIN (?:[A-Z]+ )*PRIVATE KEY(?: BLOCK)?-----([\s\S]*?)(?:-----END (?:[A-Z]+ )*PRIVATE KEY(?: BLOCK)?-----|$)/g;

/** `PO Box 4521`, `P.O. Box 88`. A box number is an address a person receives post at. */
export const PO_BOX_PATTERN = /\bP\.?\s?O\.?\s?Box\s+\d{1,6}\b/gi;

export const EMAIL_PATTERN =
  /(?<![\p{L}\p{N}._%+-])[\p{L}\p{N}._%+-]{1,64}@[\p{L}\p{N}-]+(?:\.[\p{L}\p{N}-]+)*\.[\p{L}]{2,}(?![\p{L}\p{N}_-])(?!:[\p{L}\p{N}~_\/])/gu;

/*
 * The lookaheads at the end: the TLD may not stop half-way through a word, and
 * an address followed by ":path" is an SSH remote, "git@github.com:org/repo",
 * which names a server rather than a person.
 */

/**
 * An address percent-encoded into a URL: "?email=john.smith%40gmail.com",
 * "maria%2Blists%40example.org". Agent traffic is full of query strings, and
 * the plain pattern cannot see an @ that is written %40.
 */
export const EMAIL_ENCODED_PATTERN =
  /(?<![\w.%+-])[\w.+-](?:[\w.+-]|%2[bB]){0,63}%40[\w-]+(?:\.[\w-]+){0,6}\.[A-Za-z]{2,}(?![\w-])/g;

/**
 * An address written to get past a scraper, which works just as well on a
 * redaction engine: "jsmith [at] acme [dot] com", "jsmith(at)acme.com",
 * "john dot smith at gmail dot com".
 *
 * Two forms, because the plain word "at" is everywhere in English. With a
 * bracketed [at] the rest may use real dots. With a bare " at ", every dot
 * must be spelled out as well and the ending must be a real TLD — "we met
 * at acme.com" is a sentence about a website, and "look at the dot
 * product" ends in a word no domain does.
 */
const OBF_TLD = "com|org|net|edu|gov|mil|io|co|uk|de|fr|es|it|nl|ie|ai|me|us|ca|au|in|info|biz|dev|app";
const OBF_DOT_BRACKET = String.raw`\s*[\[({<]\s*dot\s*[\])}>]\s*`;
export const OBFUSCATED_EMAIL_PATTERN = new RegExp([
  String.raw`\b[\w+-]{1,64}(?:(?:${OBF_DOT_BRACKET}|\s+dot\s+|\.)[\w+-]{1,64}){0,4}\s*[\[({<]\s*at\s*[\])}>]\s*[\w-]{1,63}(?:(?:${OBF_DOT_BRACKET}|\s+dot\s+|\.)[\w-]{1,63}){0,4}(?:${OBF_DOT_BRACKET}|\s+dot\s+|\.)(?:${OBF_TLD})\b`,
  String.raw`\b[\w+-]{1,64}(?:\s+dot\s+[\w+-]{1,64}){0,4}\s+at\s+[\w-]{1,63}(?:\s+dot\s+[\w-]{1,63}){0,4}\s+dot\s+(?:${OBF_TLD})\b`,
].join("|"), "gi");

/** 13-19 digits, optionally spaced or hyphenated in the usual groups. Length
 *  alone is far too loose — see luhn() below, which is what actually decides. */
/*
 * Groups separated by spaces or hyphens, and deliberately NOT by newlines.
 *
 * A card copied out of a receipt or a form does arrive with one group per
 * line, and this pattern was briefly widened to catch that. It matched — and
 * nothing happened, because `isSubstitutable` rejects a value carrying a
 * control character and a newline is one. The scanner found the card, the
 * alias stage dropped it, and the number went out anyway. A unit test on
 * findStructured alone said it worked, which is exactly the sort of green
 * test that is worse than no test at all.
 *
 * The rejection is not a bug to route around. Restoring a non-streamed answer
 * replaces over one whole JSON document as text, so a real value carrying a
 * newline, a quote or a backslash would be spliced in unescaped and break the
 * frame the client is parsing. Widening this needs the restore path to escape
 * what it splices, which is the most delicate code here and not something to
 * change on the way past.
 *
 * The review sheet does catch it: hiding there is a literal replacement with
 * blocks inside the document, with no JSON anywhere near it. So a card split
 * across lines in an *attachment* is found and can be hidden before sending,
 * and one split across lines typed into the composer is not. That asymmetry
 * is recorded in the tests rather than left to be rediscovered.
 */
export const CARD_PATTERN = /\b(?:\d[ -]?){12,18}\d\b/g;

/**
 * Sixteen digits on their own, written as one run, whatever the checksum
 * says: "Please use 6219710653844390 for the payment", "never share your
 * 2113610009277549 or 476 online". A card's length and a card's place in the
 * sentence; a mistyped card fails Luhn as often as a made-up one, and a
 * sixteen-digit reference that goes out as a stand-in costs nothing. On the
 * ai4privacy practice half, 381 of 775 cards in prose were missed, every one
 * of them sixteen bare digits that fail the check (2026-10-31).
 *
 * Not welded to a word, a path, a decimal or a hex literal, and not inside a
 * link. Timestamps in microseconds (16 digits from 15… to 18…) are refused by
 * the scan. A word in Korean, Japanese, Chinese or Arabic may touch it, since
 * those write a particle or a label straight onto a number: "6223563963177031을",
 * "クレジットカード番号8144035593322679".
 */
export const CARD_BARE_SIXTEEN_PATTERN = /(?<![\p{Script=Latin}\p{Script=Cyrillic}\p{Script=Greek}\p{N}_.,:\/#=+\-@$€£¥])(?<!https?:\/\/\S*)\d{16}(?![\p{Script=Latin}\p{Script=Cyrillic}\p{Script=Greek}\p{N}_\-\/@%]|[.,:]\d)/gu;

/**
 * A phone's IMEI: fifteen digits, printed AA-BBBBBB-CCCCCC-D (or with spaces)
 * on the box, the SIM tray and *#06#. The printed grouping is its own; bare
 * fifteen digits need the word IMEI or MEID before them. Luhn, like a card,
 * which is how IMEIs were caught until cards had to open with 2 to 6.
 */
export const IMEI_GROUPED_PATTERN = /\b\d{2}[ -]\d{6}[ -]\d{6}[ -]\d\b/g;
export const IMEI_CUED_PATTERN = /\b(?:IMEI|MEID)\b[^\d\n]{0,24}(\d{15})\b/gid;

/**
 * The same number with no room to breathe.
 *
 * "Card4111111111111111is on file" is what a paste out of a spreadsheet looks
 * like, and the word boundary in the pattern above cannot see it: there is no
 * boundary between "d" and "4". Digit boundaries rather than word boundaries
 * find it, and Luhn is what keeps that from being reckless — an unbroken run
 * of thirteen to nineteen digits that also passes the check digit is a card,
 * whatever it happens to be wedged between. The tracking numbers and UUIDs in
 * the negative corpus have no run that long.
 */
/** A card written in dotted groups of four, "4111.1111.1111.1111". Dots only
 *  in exactly this grouping: a looser dot would take version strings. Luhn
 *  still decides, as for every card. */
export const CARD_DOTTED_PATTERN = /(?<![\d.])\d{4}\.\d{4}\.\d{4}\.\d{4}(?![\d.])/g;

export const CARD_RUN_PATTERN = /(?<!\d)\d{13,19}(?!\d)/g;

/** Three-two-four, separated. Bare 9-digit runs are not matched: far too much
 *  of what people paste is nine digits of something else. */
export const SSN_PATTERN = /\b\d{3}-\d{2}-\d{4}\b(?!-?\d)/g;

/** The same number with the dashes left out. Nine bare digits is an order
 *  reference, an account number or a tracking id far more often than it is an
 *  SSN, so unlike the dashed form this is only taken where the user has said
 *  what it is. */
export const SSN_CUED_PATTERN =
  /\b(?:ssn|social\s+security(?:\s+(?:no\.?|number|#))?)\s*(?:(?:no\.?|number|#|is|:)\s*)*(\d{3}[\s-]?\d{2}[\s-]?\d{4})\b/gid;

/** North-American shapes plus a general +country form.
 *
 *  Guarded with digit lookarounds rather than \b. A number written the way
 *  people actually write one — "(415) 555-0143" — starts with a bracket, and
 *  \b before a bracket is not a boundary at all, so the anchored version
 *  silently matched nothing in the most common case. These guards also keep
 *  the pattern from biting ten digits out of the middle of a longer run. */
/*
 * Four shapes, and each one was a number that reached a provider before it was
 * added:
 *
 *   1-800-555-0199        the NANP trunk prefix. The lookbehind that stops a
 *                         longer number being cut in half also stopped this
 *                         one being seen at all: "800-555-0199" is preceded by
 *                         a hyphen, so the whole thing was skipped.
 *   +33 1 42 68 53 00     Paris. A single-digit city code, where the pattern
 *                         demanded at least two.
 *   0044 20 7946 0991     "00" is the same international prefix as "+" for
 *                         most of the world's dialling.
 *   07700 900123          a UK mobile written as anyone in the UK writes it.
 *                         The leading zero is the cue that separates it from a
 *                         port number or a quantity.
 *   020 7946 0142         a UK landline, which is written in three groups
 *                         rather than two — the form on nearly every British
 *                         letterhead, and one this missed entirely.
 */
export const PHONE_PATTERN = new RegExp([
  // North American, with an optional country code or trunk 1
  String.raw`(?<![\d-])(?:(?:\+|00)\d{1,3}[\s.-]?|1[\s.-])?(?:\(\d{3}\)|\d{3})[\s.-]?\d{3}[\s.-]?\d{4}(?![\d-])`,
  // International: + or 00, then groups that may start with a single digit
  String.raw`(?<![\d-])(?:\+|00)\d{1,3}[\s.-]?\d{1,4}(?:[\s.-]?\d{2,4}){2,4}(?![\d-])`,
  // An area code in brackets after the country code: "+90 (532) 123 45 67".
  String.raw`(?<![\d-])(?:\+|00)\d{1,3}[\s.-]?\(\d{1,4}\)[\s.-]?\d{2,4}(?:[\s.-]?\d{2,4}){1,3}(?![\d-])`,
  // A trunk zero, a three-digit code, then 3-2-2: "0 532 123 45 67", the
  // way Turkish numbers are written — or a mobile without its zero, 5xx then
  // 3-2-2 with one separator throughout.
  String.raw`(?<![\d-])(?:0[\s.-]?\d{3}[\s.-]\d{3}[\s.-]\d{2}[\s.-]\d{2}(?![\d-])|5\d{2}(?<trsep>[ .-])\d{3}\k<trsep>\d{2}\k<trsep>\d{2})(?![\d-])`,
  // The same with the trunk zero in brackets, as British and European
  // letterheads write it: "+44 (0)20 7946 0958".
  String.raw`(?<![\d-])(?:\+|00)\d{1,3}\s?\(0\)\s?\d{1,4}(?:[\s.-]?\d{2,4}){2,3}(?![\d-])`,
  // UK national, where the leading zero is what makes it a phone number
  String.raw`(?<![\d-])0\d{3,4}[\s.-]?\d{5,6}(?![\d-])`,
  /* UK landlines, which are written in three groups and were not matched.
  
     The rule above wants the whole subscriber number in one run — "07700
     900123" — and that is how mobiles are written. Landlines are not: it is
     "020 7946 0142" on a London letterhead and "0161 496 0118" on a Manchester
     one, area code then two groups. Every one of those went out untouched,
     which is most of the phone numbers on most business documents.
  
     Nine to thirteen digits behind a leading zero, in three groups. A sort
     code is 2-2-2 and a date is not zero-led in this shape, so neither is
     caught by it. */
  String.raw`(?<![\d-])0\d{2,4}[\s.-]\d{3,4}[\s.-]\d{3,4}(?![\d-])`,
  /* The area code in brackets with its trunk zero, "(0312) 456 7890",
     "(0151) 4960260"; and a four-digit code then the seven-digit subscriber
     number, "0131 4960497", "0909 8790437". Eleven digits either way, which
     is a whole national number in Britain, Turkey and the Philippines;
     neither was matched with no word in front (Gretel practice rows,
     2026-10-06). */
  String.raw`(?<![\d-])\(0\d{2,4}\)[ .-]?\d{3,4}[ .-]?\d{3,4}(?![\d-])`,
  String.raw`(?<![\d-])0\d{3}[ .-]\d{7}(?![\d-])`,
  /* A French number, as France writes every one: five pairs with one
     separator throughout, "06 12 34 56 78", "01.23.45.67.89". Missed with
     "Mon numéro :" in front (realistic set, 2026-10-07): the small-word cue
     wants the number straight after the word, not after a colon. */
  String.raw`(?<![\d.-])0[1-9](?<frsep>[ .])\d{2}\k<frsep>\d{2}\k<frsep>\d{2}\k<frsep>\d{2}(?![\d-]|\.\d)`,
].join("|"), "g");

/**
 * Where you live, and the numbers on the documents that prove who you are.
 *
 * These divide cleanly into two kinds, and the difference decides how each is
 * found.
 *
 * Addresses and postcodes have a shape. "418 Wexford Lane" is a number then
 * some words then one of a closed set of street words; a UK postcode is a
 * grammar you can write down. Those can be matched directly.
 *
 * A licence number does not. Driver's licences differ by state and country,
 * passports by issuing nation, tax numbers by everything — as a pattern, they
 * are "a run of letters and digits", which also describes an order reference,
 * a git commit, a product code and a flight number. Matching that shape
 * directly would redact half of what anybody pastes.
 *
 * So those are found by their *cue* instead: the words a person writes next to
 * them. Someone typing a licence number says it is a licence number, because
 * they are asking a question about it. That makes the cue more reliable than
 * the shape, and it fails in the safe direction — an unlabelled code is left
 * alone rather than a labelled one being mangled.
 */

/** The closed set that ends a street line. Ordered longest-first inside the
 *  alternation so "Street" wins over "St" and the match does not stop early. */
/**
 * The word that ends a street name, in two tiers.
 *
 * The first list was written against British addresses and scored 7.9% on a
 * public American corpus — the misses were Spur, Run, Trail, Harbors, Shore,
 * Stravenue and the rest of the USPS suffix table, which Faker uses in full.
 * Adding the table outright took the corpus to 24% and redacted "3 Park
 * benches", "15 Union members" and "4 View permissions" out of ordinary
 * sentences, which is a worse product than the one that missed the addresses.
 *
 * So: a word that is only ever a street suffix can be trusted anywhere, and
 * a word that is also ordinary English has to end its clause. An address is
 * the last thing in its phrase — "390, Wiza Spur." or "Waters Harbors," —
 * whereas a count is followed by the thing being counted, in lower case.
 * That single lookahead is the whole difference, and it is the same guard
 * STANDALONE_STREETS has always used for "350 Broadway".
 */
const STREET_WORDS_STRONG = [
  "Street", "Boulevard", "Crescent", "Terrace", "Gardens", "Avenue", "Parkway",
  "Highway", "Square", "Circle", "Court", "Close", "Drive", "Grove", "Lane",
  "Road", "Mews", "Alley", "Bypass", "Causeway", "Expressway", "Freeway",
  "Motorway", "Turnpike", "Stravenue", "Throughway", "Trafficway", "Viaduct",
  "Overpass", "Underpass", "Skyway", "Esplanade",
  // Abbreviations last: a longer name must win the span first.
  "Blvd", "Ave", "Rd", "Str", "Sq", "St", "Ln", "Dr", "Ct", "Pl", "Trl", "Hwy", "Pkwy",
].join("|");

/**
 * The strong words, less "Court", for the branches that have no building
 * number to stand on. "12 Harbour Court" is an address; "to the Supreme
 * Court" and "at the Warsaw Regional Court" are institutions, and every
 * judgment in the Text Anonymization Benchmark (ECHR court cases) is full of
 * them — 358 were redacted as addresses before this list existed.
 */
const STREET_WORDS_STRONG_NUMBERLESS = STREET_WORDS_STRONG.split("|").filter((w) => w !== "Court" && w !== "Ct").join("|");

/** Also ordinary words. Reached only when nothing lower-case follows, so the
 *  street is the end of its phrase rather than a count of something. */
const STREET_WORDS_WEAK = [
  "Walk", "Rise", "Row", "Way", "Ways", "Place", "Bend", "Burg", "Center",
  "Cliffs", "Cliff", "Corners", "Corner", "Course", "Coves", "Cove", "Creek",
  "Crossing", "Crest", "Dale", "Divide", "Estates", "Estate", "Extension",
  "Falls", "Fields", "Field", "Flats", "Flat", "Ford", "Forest", "Forks",
  "Fork", "Gateway", "Glen", "Green", "Harbors", "Harbor", "Haven", "Heights",
  "Hills", "Hill", "Hollow", "Inlet", "Island", "Isle", "Junction", "Key",
  "Knolls", "Knoll", "Lakes", "Lake", "Landing", "Land", "Locks", "Lock",
  "Lodge", "Loop", "Manor", "Meadows", "Meadow", "Mills", "Mill", "Mission",
  "Mountain", "Mount", "Neck", "Orchard", "Oval", "Park", "Passage", "Pass",
  "Path", "Pike", "Plains", "Plain", "Points", "Point", "Port", "Prairie",
  "Ranch", "Rapids", "Rest", "Ridge", "River", "Run", "Runs", "Row", "Rows", "Shoals", "Shoal", "Shores",
  "Shore", "Springs", "Spring", "Spurs", "Spur", "Station", "Stream", "Summit",
  "Trace", "Track", "Trail", "Tunnel", "Unions", "Union", "Valley", "Views",
  "View", "Village", "Ville", "Vista", "Wells", "Well", "Wynd",
  // Observed in the public corpus and nowhere in the list above. Plurals
  // mostly: Faker pluralises half the USPS table and the singular form does
  // not match "Christian Greens".
  "Greens", "Common", "Commons", "Walks", "Ramp", "Ramps", "Squares",
  "Grounds", "Radial", "Croft", "Mall", "Burgs", "Villages", "Ports",
  "Manors", "Circles", "Courts", "Parks", "Stations", "Bridge", "Fall",
  "Divides", "Gateways", "Glens", "Havens", "Islands", "Junctions",
  "Landings", "Lodges", "Missions", "Mounts", "Necks", "Orchards", "Ovals",
  "Passages", "Paths", "Pikes", "Prairies", "Ranches", "Ridges", "Rivers",
  "Summits", "Traces", "Tracks", "Trails", "Tunnels", "Valleys", "Vistas",
  // The rest of the USPS suffix table, which Faker draws from: "34853 Fisher
  // Fords", "275 Kassulke Pines", "Delpha Streets" (2026-10-04).
  "Fords", "Pines", "Pine", "Brooks", "Brook", "Branch", "Canyon", "Cape",
  "Crossroad", "Curve", "Drives", "Extensions", "Ferry", "Forge",
  "Forges", "Fort", "Groves", "Keys", "Lights", "Loaf", "Mountains",
  "Plaza", "Roads", "Streets", "Avenues", "Lanes", "Wall", "Camp", "Club",
].join("|");

/** A word in a script other than Latin, or a colon, then a space: where a
 *  street written in Latin letters starts inside Hindi, Telugu, Arabic,
 *  Chinese or Russian text, or after a label. */
const NON_LATIN_BEFORE = String.raw`[\p{Script=Devanagari}\p{Script=Telugu}\p{Script=Tamil}\p{Script=Bengali}\p{Script=Gujarati}\p{Script=Kannada}\p{Script=Malayalam}\p{Script=Gurmukhi}\p{Script=Arabic}\p{Script=Hebrew}\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Hangul}\p{Script=Cyrillic}\p{Script=Thai}\p{Script=Greek}][\p{M}]*[:：]?[ \t]+`;

/** The small words a street may stand before and still be the end of its
 *  phrase: "856 Bridget Dale in Worcestershire", "1502 Mante Creek on
 *  Tuesday", "4468 Baumbach Station or …". A count is followed by what it
 *  counts ("5 Green Park tickets"), which is never one of these. */
const AFTER_A_STREET = String.raw`(?:in|on|at|is|was|will|or|and|by|from|near|has|had|tomorrow|today|yesterday|facility|location|office|building|branch|site|house|apartment|street|road|area|est|et|pour|avec|dans|sont|und|ist|wird|für|zu|am|e|è|per|con|alle|nella)`;

/** The words that put somebody on a street in French, German and Italian,
 *  for the numberless branches: "à Fritz Street", "situé au School Close",
 *  "in der Meadow Lane", "presso Helmer Lights", "in via New Street". The
 *  street names in ai4privacy's French, German and Italian rows are English,
 *  and the English cues never fired on them. */
const STREET_CUES_INTL = String.raw`(?<![\p{L}])(?:à|au|aux|sur|rue|situé(?:e)?\s+(?:à|au|sur)|dans\s+la\s+rue|in\s+der|an\s+der|auf\s+der|bei|lautet|Straße|befindet\s+sich\s+(?:in\s+der|in|im)|presso|in\s+via|situat[oa]\s+(?:a|in)|al|alla|indirizzo\s+è)`;

/**
 * Streets whose name is the whole of it.
 *
 * "350 Broadway" and "12 Kingsway" are addresses with no street word in them,
 * and they were the largest single group the scanner missed — the corpus had
 * both and neither was found. A general rule cannot help here: a number
 * followed by any capitalised word would redact "42 Answers" and half of
 * ordinary prose. A list of the names that actually work this way can, and it
 * is short because the pattern is rare.
 */
const STANDALONE_STREETS =
  "Broadway|Kingsway|Piccadilly|Strand|Esplanade|Embankment|Concourse|Parade|Promenade|Whitehall|Cheapside";

/** The words that come before a name in most of Europe, where the street word
 *  leads rather than follows: "3 Rue Lafayette", "10 Via Roma". Still anchored
 *  to a building number, so the branch cannot fire on prose. */
const STREET_PREFIXES =
  "Rue|Via|Viale|Vicolo|Piazzetta|Largo|Calle|Carrer|Avenida|Plaza|Paseo|Piazza|Corso|Strasse|Straße|Platz|Gasse|Rua|Travessa|Praça|Vei|Gata|Gracht|Laan|Boulevard|Quai|Chemin|ul\\.|Ulica|Aleja|trg|Trg|" +
  // Spanish road words the multilingual set writes: "Camino del Villar 88",
  // "Carretera Ciudad Obregón-Hermosillo 845", "Ruta de la Costa Vasca 325".
  "Carretera|Camino|Ruta|Travesía|Barrio|Callejón|Ronda|Glorieta|Cuesta|Pasaje|Urbanización|Avinguda|Passeig|Estrada";

/** The small words between a European street word and its name: "Rue du
 *  Faubourg", "Calle de Alcalá", "Via della Spiga". Lower-case, so without
 *  them the name after the street word could never start. */
const STREET_PARTICLES = String.raw`(?:(?:de|du|des|del|de\s+la|de\s+las|de\s+los|della|delle|dei|di|da|do|dos|das|la|le|les|van|von|der|den|De\s+La|De|Du|Des|Del|Della|Di|Da|Do|Dos|Das|La|Le|Les)\s+)`;

/**
 * A street with no number, by the shape of its name alone (2026-10-31): the
 * multilingual set asks about "Moscrop Street", "Engenser Weg", "Calle
 * Hidalgo" and "Waldliesborner Straße" with no house number anywhere, and
 * every one went out as written. Two shapes, each one a street and rarely
 * anything else:
 *
 *   - capitalised words and an English street word that is never ordinary
 *     English ("Nashville Road", "Gangoh Road"). Not "Court", which is a
 *     court far more often, nor "Drive" and "Crescent" (Google Drive, the
 *     Red Crescent);
 *   - a German place adjective and a street word ("Birkenlacher Weg",
 *     "Radeberger Landstraße").
 *
 * A well-known street alone is nobody's address, and the tests keep it so:
 * "Hauptstraße", "Calle Ocho" and "Rue de Miromesnil" stay, which is why a
 * welded German name and a Romance street word with a name are not read
 * here. The famous streets (FAMOUS_STREETS) are refused by the scan.
 */
export const STREET_NUMBERLESS_PATTERN = new RegExp([
  String.raw`(?<![\p{L}\p{N}])(?:(?!(?:The|A|An|In|At|On|To|From|Near|Dear|Our|Your|My|His|Her|Their|Visit|Please|And|Or|Via|By|For|Of|Off|Along|Into|Onto|Across|This|That|New|Old)[ \t])\p{Lu}[\p{L}'’-]*[ \t]+){1,3}(?:${STREET_WORDS_STRONG_NUMBERLESS.split("|").filter((w) => /^[A-Z][a-z]{3,}$/.test(w) && w !== "Drive" && w !== "Crescent").join("|")})(?![\p{L}\p{N}])`,
  String.raw`(?<![\p{L}\p{N}])\p{Lu}\p{Ll}{2,}er[ \t]+(?:Straße|Strasse|Weg|Allee|Platz|Ring|Damm|Gasse|Chaussee|Landstraße|Steig|Pfad)(?![\p{L}\p{N}])`,
].join("|"), "gu");

/** Street words that are welded onto the name in German and Dutch:
 *  "Hauptstraße", "Kalverstraat", "Keizersgracht". The house number follows. */
const STREET_SUFFIXES_WELDED = "straße|strasse|str\\.?|gasse|allee|platz|damm|weg|straat|laan|gracht|plein|steeg|katu|kuja|polku|gatan|vägen|gränd|vej|vænget|gade|veien|vegen|gata|stien|tänav|iela|" +
  // Finnish -tie (road), Danish -stræde, Icelandic -braut and -stræti, Dutch
  // -hove, Frisian -wei, Swedish -väg, Norwegian -bakken. -tie after four
  // letters at least: French "Partie 2" is the second part of a lab report
  // (WildChat), "Mannerheimintie 5" a road.
  "(?<=\\p{L}{4})tie|stræde|straede|braut|stræti|straeti|hove|wei|väg|bakken|" +
  // Dutch dikes, quays and canals: "Rijndijk 41", "Houtribdijk 60".
  "dijk|kade|singel|dreef|baan|markt";

/** The parts of a street name that are not capitalised words: a compass
 *  direction, and a numbered street. "500 W 2nd Ave" is made of both, and the
 *  old pattern could match neither. */
const NAME_WORD = String.raw`(?:[A-Z][\p{L}'’-]*|\d{1,3}(?:st|nd|rd|th)|[NSEW]|N[EW]|S[EW])\s+`;
/** The same, on one line. A building number and the words of its street are
 *  written together: "779\nBILL TO\nSummit" is the end of an odometer line, a
 *  heading and an insurer's name, not a street — and it was replaced as one,
 *  which put a made-up street where "Summit Mutual Insurance" was. */
const NAME_WORD_H = String.raw`(?:[A-Z][\p{L}'’-]*|\d{1,3}(?:st|nd|rd|th)|[NSEW]|N[EW]|S[EW])[ \t]+`;

/** A cell that is a street and nothing else: "Albany Road", "W 2nd Street",
 *  "The Causeway". Read only in a row that is somebody's record (see
 *  redactionRows), where a cell is a whole value and needs no number. */
export const STREET_CELL_PATTERN = new RegExp(
  String.raw`^(?:${NAME_WORD_H}){1,4}(?:${STREET_WORDS_STRONG}|${STREET_WORDS_WEAK})$|^The[ \t]+(?:${STREET_WORDS_STRONG})$`,
  "u",
);

/** A building number, up to four name words, then a street word, and a
 *  compass quadrant if one follows ("100 King St W", "1600 Main St NW"). */
/** A building number, up to four name words, then a street word. The name
 *  words are capped: without a cap the pattern will happily swallow a whole
 *  sentence that happens to end in "Way". */
/* A comma is allowed after the building number. "390, Wiza Spur" and
   "4546, Monique Circle" are how a good deal of the corpus writes an address,
   and requiring whitespace alone sent every one of them through whole. */
export const ADDRESS_PATTERN = new RegExp([
  String.raw`\b\d{1,5}[A-Za-z]?,?[ \t]+(?:${NAME_WORD_H}){1,4}(?:${STREET_WORDS_STRONG})\b(?:\.?[ \t]+(?:[NS][EW]?|[EW])\b(?![\p{L}'’.-]))?(?:,?\s+(?:Apt|Apartment|Suite|Ste)\.?\s*#?\s*[A-Za-z]?\d{1,6}[A-Za-z]?)?\.?`,
  // The ordinary-word tier, behind the clause-ending guard.
  String.raw`\b\d{1,5}[A-Za-z]?,?[ \t]+(?:${NAME_WORD_H}){1,4}(?:${STREET_WORDS_WEAK})\b(?:,?\s+(?:Apt|Apartment|Suite|Ste)\.?\s*#?\s*[A-Za-z]?\d{1,6}[A-Za-z]?)?\.?(?!\s+(?!${AFTER_A_STREET}\b)[a-z])`,
  // Both of the branches below are a number followed by a name, which is also
  // the shape of a count: "2 Broadway tickets", "4 Via Rail passes". The
  // street-word branch above needs no such guard, because the street word is
  // its own evidence. Here the evidence is what follows — an address ends its
  // clause, so a lower-case word after it means the number was counting
  // something. It costs "350 Broadway and I'll see you there", and precision
  // is worth more than that sentence.
  String.raw`\b\d{1,5}[A-Za-z]?\s+(?:${STANDALONE_STREETS})\b(?!\s+[a-z])`,
  // The first guard is not decoration. With only the lower-case lookahead, the
  // engine satisfied it by backtracking inside the street name itself — "4 Via
  // Rail passes" matched "4 Via Rai", one letter short, which is a redaction
  // that mangles the word it was trying not to take.
  String.raw`\b\d{1,5}[A-Za-z]?\s+(?:${STREET_PREFIXES})\s+(?:${STREET_PARTICLES})?[A-Z][\p{L}'’-]*(?:\s+[A-Z][\p{L}'’-]*)?(?:[ \t]+(?!(?:19|20)\d\d\b)\d{1,4}[a-z]?(?![\p{L}\p{N}]))?(?![\p{L}'’-])(?!\s+[a-z])`,
  // The European forms where the number follows the name: "Hauptstraße 5",
  // "Kalverstraat 92", "Calle Mayor 12", "Via Roma 10". A year after the name
  // is not a house number, which is what keeps "Via Rail 2024" a sentence.
  String.raw`\b[A-Z][\p{L}'’-]*(?:${STREET_SUFFIXES_WELDED})\s+(?!(?:19|20)\d\d\b)\d{1,4}[a-z]?(?!\d)`,
  String.raw`\b(?:${STREET_PREFIXES})\s+(?:${STREET_PARTICLES})?[A-Z][\p{L}'’-]*(?:\s+[A-Z][\p{L}'’-]*)?,?\s+(?!(?:19|20)\d\d\b)\d{1,4}[a-z]?(?!\d)`,
  // Spanish, Catalan, Portuguese, French and Italian prose write the street
  // word in lower case: "el piso de calle Alcalá 214", "moro na rua Augusta
  // 1500". Not "via" or "corso", which are English words before a name and a
  // number: "sent via DHL 2 days ago".
  String.raw`(?<![\p{L}])(?:calle|avenida|paseo|carrer|rua|rue|piazza)\s+(?:${STREET_PARTICLES})?[A-Z][\p{L}'’-]*(?:\s+[A-Z][\p{L}'’-]*)?,?\s+(?!(?:19|20)\d\d\b)\d{1,4}[a-z]?(?!\d)`,
  // German and Austrian with the street word apart from the name:
  // "Koepenicker Str. 74", "Mariahilfer Straße 12".
  String.raw`\b[A-Z][\p{L}'’-]+\s+(?:Str\.|Straße|Strasse|Gasse|Weg|Allee|Platz|Ring|Damm)\s+(?!(?:19|20)\d\d\b)\d{1,4}[a-z]?(?!\d)`,
  // A street named after somebody, joined with hyphens and the street word
  // capitalised: "Kurt-Oster-Straße 145", "Konrad-Adenauer-Allee 3",
  // "Fritz-Huber-Str. 12" — the standard German way to name a street for a
  // person, and none of the forms above took it (the welded words are lower
  // case, the separate ones need a space). Found by the multilingual benchmark.
  String.raw`\b[A-Z][\p{L}'’]*(?:-[\p{L}'’]+)*-(?:Straße|Strasse|Str\.|Allee|Weg|Platz|Gasse|Ring|Damm|Ufer|Chaussee|Steig|Pfad|Markt)\s+(?!(?:19|20)\d\d\b)\d{1,4}[a-z]?(?!\d)`,
  // Hungarian, where the street word follows the name and is abbreviated:
  // "Kálmán Imre u. 12.", "Csabai kapu 39.", "Árpád fejedelem útja 62."
  String.raw`\b[A-ZÁÉÍÓÖŐÚÜŰ][\p{L}'’-]+(?:\s+[\p{L}'’-]+)?\s+(?:u\.|utca|út|útja|tér|körút|krt\.|rakpart|sétány|köz|kapu|sor)\s+\d{1,4}\.?`,
  // A street with no number in front of it, found the way an account number
  // is: by the word that introduces it.
  //
  // Most of what this engine still misses on the public corpus is this —
  // "moved to Veterans Memorial Highway", "residing at St Mary's Road",
  // "our clinic at S Broadway". There is no building number to anchor on and
  // no honest way to match a capitalised phrase on its last word alone, so
  // the anchor is the preposition instead.
  //
  // Strong suffixes only, and the clause guard as well. Both are needed: the
  // weak tier would take "at Green Park" and "to Union Station", and without
  // the guard "at Abbey Road studios" loses the studios.
  // A flat or suite number that is part of an address, rather than one on
  // its own.
  //
  // "Suite 300, second floor." is deliberately not an address — a suite
  // number identifies nobody, and redaction.eval and scanner-safety both
  // hold that line. "9230 Christian Greens, Apt. 447" and "Apt. 881, 28802"
  // are a different thing: the flat number is sitting inside an address that
  // has already proved itself with a street or a postcode, and taking the
  // street while leaving the flat is redacting half a door.
  //
  // So the cue is never trusted on its own here. Either a street run comes
  // before it, or a postcode follows it. The bare form stays unmatched, and
  // the tests that require that still pass.
  String.raw`(?:${NAME_WORD}){1,4}(?:${STREET_WORDS_STRONG}|${STREET_WORDS_WEAK})[,\s]+(?:Apt|Apartment|Suite|Ste)\.?\s*#?\s*[A-Za-z]?\d{1,6}[A-Za-z]?\b`,
  String.raw`\b(?:Apt|Apartment|Suite|Ste)\.?\s*#?\s*[A-Za-z]?\d{1,6}[A-Za-z]?,\s*\d{5}(?:-\d{4})?\b`,
  // A flat number on the line under a street, as an address block puts it:
  // "Søndergade 52\n Apt. 656", "52 Huntly Street\n Suite 132". Only the flat
  // is taken: a value with a line break in it cannot be substituted, so the
  // street above is found on its own line by the branches above.
  String.raw`(?<=(?:[A-Z][\p{L}'’-]*(?:${STREET_SUFFIXES_WELDED})\s+\d{1,4}[a-z]?|(?:${NAME_WORD}){1,4}(?:${STREET_WORDS_STRONG}|${STREET_WORDS_WEAK})(?:\s+[NSEW]{1,2})?|(?:${STREET_PREFIXES})\s+(?:${STREET_PARTICLES})?[A-Z][\p{L}'’-]*(?:\s+[A-Z][\p{L}'’-]*)?\s+\d{1,4}[a-z]?)[ \t,]*\r?\n[ \t>?]*)(?:Apt|Apartment|Suite|Ste)\.?\s*#?\s*[A-Za-z]?\d{1,6}[A-Za-z]?\b`,
  // A street with its number after it rather than before.
  //
  // "a property at Kuhlman Run 755", "our clinic at S Broadway 61915",
  // "See us at Arnaldo Rapids, 5279" — the number follows the name, which
  // every branch above assumes it cannot. Anchored by the preposition, for
  // the same reason the numberless branch below is: without it, any
  // capitalised phrase ending in a street word and followed by a figure
  // would qualify, and "Q3 Revenue Park 2024" is a sentence somebody writes.
  String.raw`(?<=\b(?:at|on|in|to|from|near)\s(?:(?:the|our|your|their|his|her|my|its)\s+)?)(?:${NAME_WORD}){1,4}(?:${STREET_WORDS_STRONG}|${STREET_WORDS_WEAK}),?\s+\d{1,5}\b`,
  // The second street of a pair.
  //
  // "Mill Road and Stoltenberg Avenue" — the first is found by whatever
  // introduced it and the second by nothing at all, because "and" is not a
  // preposition and there is no number in front of it.
  //
  // Not when the name goes on: "the Red Cross and Red Crescent Societies" is
  // an organisation, and "William Gibson and Michael St. John Smith" a saint's
  // name in a person's (Dolly 15k). A street pair ends its phrase.
  String.raw`(?<=\b(?:and|&)\s)(?:${NAME_WORD}){1,4}(?:${STREET_WORDS_STRONG_NUMBERLESS})\b(?!\s+[a-z])(?![ \t]+(?!(?:${STREET_WORDS_STRONG})\b)\p{Lu})(?!(?<=St)\.[ \t]*\p{Lu})`,
  // A flat number after a building number, or after the word "address".
  //
  // "the event will be held at 1913 Suite 786" and "send resume to address
  // Suite 886" are both addresses whose first half is not a street this
  // engine recognises — a bare building number, or the word address itself.
  // Either is evidence enough for the flat number beside it.
  String.raw`\b\d{1,5}[A-Za-z]?,?\s+(?:Apt|Apartment|Suite|Ste)\.?\s*#?\s*[A-Za-z]?\d{1,6}[A-Za-z]?\b`,
  String.raw`(?<=\baddress\s)(?:Apt|Apartment|Suite|Ste)\.?\s*#?\s*[A-Za-z]?\d{1,6}[A-Za-z]?\b`,
  // A flat number a sentence sends somebody to.
  //
  // "Accommodations will be at Apt. 259", "documents mailed to Suite 798",
  // "our courts at Suite 435" — 121 of the corpus's address values are a
  // flat number introduced by a preposition, and the branches above cannot
  // see them: there is no street before and no postcode after, only the word
  // that says this is a place.
  //
  // The capital is doing the work, as it is everywhere else the word "suite"
  // appears in this file. "ran at suite 7" is a test suite and stays one.
  // And "Suite 300, second floor." has no preposition in front of it, which
  // is why that sentence is still untouched and its test still passes.
  String.raw`(?<=\b(?:at|to|in|from|near|into|alert|contact)\s(?:(?:the|our|your|their|his|her|my|its)\s+)?(?:suite|apartment|flat)?\s*)(?:Apt|Apartment|Suite|Ste)\.?\s*#?\s*[A-Za-z]?\d{1,6}[A-Za-z]?\b`,
  // A street with a postcode after it and no number in front.
  //
  // "Waters Harbors, 63399" and "Mitchell Stream, 95254-9754" have no
  // building number to anchor on and no preposition either, so neither of
  // the branches around this one can see them. What they do have is a
  // postcode sitting immediately after, which is as good an anchor as a
  // number in front — nothing but an address is written that way.
  //
  // The whole run is taken, street and postcode together: they are one thing
  // and splitting them would leave the code readable beside a redacted
  // street, which tells a reader the town anyway.
  String.raw`(?:${NAME_WORD}){1,4}(?:${STREET_WORDS_STRONG}|${STREET_WORDS_WEAK})\s*,\s*\d{5}(?:-\d{4})?\b`,
  // A lookbehind, so the preposition stays in the sentence. Every other
  // branch here matches the address and nothing else, and scan() takes the
  // whole match; a capture group would have made this the one branch whose
  // value included the word in front of it.
  String.raw`(?<=\b(?:at|on|in|to|from|near|visit|located\s+at|residing\s+at|address\s+is)\s(?:(?:the|our|your|their|his|her|my|its)\s+)?)(?:${NAME_WORD}){1,4}(?:${STREET_WORDS_STRONG_NUMBERLESS})\b(?!\s+(?!${AFTER_A_STREET}\b)[a-z])(?!(?<=St)\.[ \t]*\p{Lu})`,
  // French, Spanish and Portuguese written as people type them: the street
  // word in lower case and the name too — "36 rue de pologne", "33 avenue de
  // Provence", "C/ Señores Curas 88", "Avda. Rio Nalon 58", "Rua Diadema
  // 1903". These street words are not English words, so a building number
  // before one, or a number after the name, is enough. "Via" and "place"
  // stay capitalised-only in the branches above: "sent 2 via email".
  // After a lower-case street word, the name starts with a particle or a
  // capital ("rue de pologne", "rue Lafayette"): "rue" is also an English
  // verb, and "3 rue changes" is a plan. After the first word, only capitals
  // and particles, so the name ends where the sentence resumes.
  String.raw`\b\d{1,5}[A-Za-z]?,?\s+(?:(?:rue|avenue|boulevard|avenida|avda\.|av\.|rua|rúa|calle|chemin|allée|impasse|quai)\s+(?:${STREET_PARTICLES}[\p{L}'’-]{2,}|\p{Lu}[\p{L}'’-]+)|(?:Rue|Av\.?|Avda\.|Rúa|Rua|Avenida|Calle|C\/)\s+(?:${STREET_PARTICLES})?[\p{L}'’-]{2,})(?:[ \t]+(?:${STREET_PARTICLES})?\p{Lu}[\p{L}'’-]*){0,3}`,
  String.raw`(?<![\p{L}\d])(?:(?:rue|avenida|rua)\s+(?:${STREET_PARTICLES}[\p{L}'’-]{2,}|\p{Lu}[\p{L}'’-]+)|(?:Avda\.|Av\.|Rúa|C\/)\s+(?:${STREET_PARTICLES})?[\p{L}'’-]{2,})(?:[ \t]+(?:${STREET_PARTICLES})?\p{Lu}[\p{L}'’-]*){0,3}[ \t]+(?!(?:19|20)\d\d\b)\d{1,4}[a-z]?(?!\d)`,
  // Greek: Λεωφόρος (avenue), Οδός (street), Πλατεία (square) and their
  // abbreviations, then the name and a number; or a number before.
  String.raw`(?<![\p{L}\d])(?:Λεωφόρος|Λεωφ\.|Λ\.|Οδός|Οδ\.|Πλατεία|Πλ\.)\s+[\p{L}'’-]+(?:\s+[\p{L}'’-]+){0,2}\s+\d{1,4}`,
].join("|"), "gu");

/**
 * The two streets of a corner: "the corner of Csabai kapu 39. and Mathias
 * Pass", "corner of heiligengeistbrücke 77 and minik courts". The cue is the
 * evidence for both, so each side is taken up to its punctuation, as long as
 * it has a capital or a number in it and does not open with "the" — "the
 * corner of the room and the window" is furniture.
 */
export const CORNER_PATTERN =
  /\b[Cc]orner\s+of\s+((?:\d{1,5}\s+)?[\p{L}][\p{L}'’.-]*(?:[ \t]+[\p{L}\d][\p{L}\d'’.-]*){0,4}?)[ \t]+(?:and|&)[ \t]+((?:\d{1,5}\s+)?\p{L}(?:[\p{L}'’.-]*[\p{L}'’-])?(?:[ \t]+\p{L}(?:[\p{L}'’.-]*[\p{L}'’-])?){0,3}(?:[ \t]+\d{1,5}\.?)?)(?=[ \t]*(?:[,;!?)\n]|\.(?:\s|$)|$))/gdu;

/** The second street of a corner that the sentence goes on after: "the
 *  corner of Dunajska 97 and Dolgorukova Tunnel after the concert". Capitals
 *  only here, so the name stops where the lower-case sentence resumes. */
export const CORNER_SECOND_PATTERN = new RegExp(
  String.raw`\b[Cc]orner\s+of\s+(?!(?:the|a|an|my|our|your|his|her|their|this|that)\b)[\p{Lu}\d][^\n]{0,60}?[ \t]+(?:and|&)[ \t]+((?:\d{1,5}[ \t]+)?(?:\p{Lu}[\p{L}\p{M}'’.-]*[ \t]+){1,3}(?:(?:${STREET_WORDS_STRONG}|${STREET_WORDS_WEAK})\b|\d{1,5}\.?))(?=[ \t]+\p{Ll})`,
  "gdu",
);

/**
 * A street that is only a name and a number — "Parmova 109", "Allika 46",
 * "450 Præstevænget 15" — found by the phrase that introduces it.
 *
 * Most of the world's streets carry no street word this file knows, and a
 * capitalised word and a number is otherwise the shape of "Gate 5",
 * "Windows 11" and "Chapter 12". So the cue carries the whole weight, and
 * only the unambiguous ones count: an address being given ("my new address
 * is", "located at", "lives at"), a destination ("return to", "deliver to",
 * "a taxi to"), a meeting place ("meet me at", "drops you off at"). The bare
 * prepositions are not enough and are not in the list.
 *
 * Measured on Microsoft's Presidio Research corpus, whose templates use
 * exactly these phrases, and held back by the words that follow them in
 * ordinary prose (gate, room, floor, a month, a product).
 */
/* One line, and no full stop inside the name: the Text Anonymization
   Benchmark's judgments say "lives in Bytom.\n\nOn 17 November …", and the
   first version of this read the city, the paragraph break and the date as
   one street. */
const ADDRESS_CUE = String.raw`(?:(?:[Nn]ew\s+|[Hh]ome\s+|[Bb]illing\s+|[Pp]ostal\s+|[Mm]ailing\s+|[Ss]hipping\s+|[Dd]elivery\s+|[Mm]y\s+|[Oo]ur\s+|[Hh]is\s+|[Hh]er\s+|[Tt]heir\s+)?[Aa]ddress(?:\s+is|\s+was)?\s*:?|[Ll]ocated\s+at|(?:[Ll]ives?|[Ll]ived|[Ll]iving|[Rr]esides?|[Rr]esiding|[Ss]tay(?:s|ing)?)\s+(?:at|in|on)|[Rr]eturn(?:ed)?\s+(?:it\s+|them\s+)?to|(?:[Ss]en[dt]|[Dd]eliver(?:ed)?|[Ss]hip(?:ped)?|[Mm]ail(?:ed)?|[Pp]ost(?:ed)?|[Ff]orward(?:ed)?)\s+(?:it\s+|them\s+|this\s+|the\s+\w+\s+|a\s+new\s+one\s+)?to|(?:[Oo]ffice|[Ss]hop|[Ss]tore|[Cc]linic|[Rr]estaurant|[Hh]ouse|[Ff]lat|[Aa]partment)\s+is\s+(?:at|on)|(?:is|are)\s+located\s+(?:at|on)|[Cc]orner\s+of|[Tt]axi\s+to|[Dd]rops?\s+(?:you|me|him|her|them|us)\s+off\s+at|[Mm]eet\s+(?:me|you|us|them)\s+at|[Mm]oved\s+to|[Vv]isit\s+(?:us|me)\s+at|[Ll]etter\s+arrived\s+at)`;
const NOT_A_STREET = String.raw`(?:Gate|Room|Floor|Level|Terminal|Platform|Suite|Unit|Box|Chapter|Section|Page|Part|Step|Stage|Phase|Version|Windows|Python|iOS|Android|Office|Series|Model|Table|Figure|Row|Seat|Hall|Building|Block|Wing|Door|Aisle|Lane\s+\d|Week|Day|Year|Q[1-4]|January|February|March|April|May|June|July|August|September|October|November|December|Jan|Feb|Mar|Apr|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec|Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday)\b`;
/** Street words written in lower case after the name: Norwegian "gate",
 *  Hungarian "utca", Polish "ulica", Danish "allé", Finnish "katu". */
const LOWER_STREET_WORDS = "gate|gata|gatan|vei|veien|vej|vegen|väg|vägen|utca|út|útja|tér|körút|ulica|ulice|iela|gatvė|tänav|tee|straße|strasse|weg|laan|straat|allé|allee|alle|gasse|gade|plads|stræde|tie|katu|kuja|polku|vegur|rue|via|calle|rua";
export const NOT_A_STREET_PATTERN = new RegExp(String.raw`\b${NOT_A_STREET}|\b(?:Pier|Lot|Dock|Berth|Bay|Hangar|Studio|Stand|Stage|Court|Field|Pitch|Track|Team|Batch|Squad|Class|Grade|Finance|Sales|Marketing|Legal|Support|Engineering|Accounts|Accounting|Payroll|Operations|Ops|HR|IT|Admin|Desk|Queue|Tier|Group|Department|Dept|Year|Zone|Sector|Area|District|Ward|Route|Bus|Train|Flight|Line)\b`);
export const ADDRESS_CUED_PATTERN = new RegExp(
  String.raw`(?<=\b${ADDRESS_CUE}\s+(?:(?:[Tt]he|[Oo]ur|[Mm]y|[Yy]our|[Hh]is|[Hh]er|[Tt]heir)\s+)?)(?:\d{1,5}[A-Za-z]?,?\s+)?[\p{Lu}][\p{L}'’-]+(?:[ \t]+(?:[\p{Lu}][\p{L}'’-]*|de|du|des|del|di|da|van|von|der|la|le|u\.|ul\.|${LOWER_STREET_WORDS})){0,3}[ \t]+(?!(?:19|20)\d\d\b)\d{1,5}[A-Za-z]?(?:[ \t]*[/-][ \t]*\d{1,4})?(?:[ \t][A-Z](?![\p{L}\d]))?(?![\p{L}\d])`,
  "gu");

/**
 * A street under a label that says it is one, in the seven languages of the
 * business benchmark: "Street Address: 7463 Katrina Keys", "Indirizzo: 7
 * Canale Arnulfo", "Straße: Trudel-Lübs-Ring 6", "Adress: Studio 9, Cheryl
 * corners", "con domicilio en calle del Sol 10", `<streetAddress>133 Harper
 * Garden, Suite 388`, `"street_address": "32456 Snyder Roads"`.
 *
 * Business paperwork names its streets with words no list here can hold —
 * Faker's "Keys", "Fort" and "Curve", and Spanish, Italian and Swedish street
 * types in documents written in another language — so after a label the
 * shape is enough: a building number and capitalised words, capitalised words
 * and a building number, or a flat or studio and then the street. It stops at
 * the first comma or line break, which keeps the town out of it (the
 * postcode and place patterns have those) and a sentence from running on.
 * A lower-case word is taken only as the last word before that stop:
 * "148 Donald mills", "04 Shaw landing".
 *
 * ADDRESS_CUED_PATTERN above handles the English phrases with a name then a
 * number; this is the rest, and the scan turns down a value whose label is
 * about a machine ("IP address", "MAC address", "email address").
 */
const ADDRESS_FIELD = String.raw`(?:(?:street|postal|post|mailing|billing|shipping|home|delivery|residential|registered|business|physical|property|correspondence)[\s_\\-]*)?(?:address(?:[\s_\\-]*line[\s_\\-]*\d?)?|addr)|adresse|adress|adres|straatadres|gatuadress|postadress|postadresse|wohnadresse|anschrift|stra(?:ß|ss)e|straat|gata|indirizzo(?:\s+(?:postale|di\s+residenza|di\s+domicilio))?|direcci[óo]n(?:\s+postal)?|domicilio|domicile|residenza|streetaddress|streetname`;
const ADDRESS_PHRASE = String.raw`located\s+at|resid(?:es|ing|ent)\s+at|(?:with\s+)?(?:a|an|the|its|his|her|their)\s+(?:residence|address|domicile|home)\s+at|(?:current|home|registered|mailing|street)\s+address\s+at|(?:street\s+)?address(?:\s+on\s+(?:file|record))?\s+is|demeurant(?:\s+(?:au|à|a))?|lives?\s+at|living\s+at|at\s+the\s+following\s+address|dont\s+l['’]\s?adresse\s+est|r[ée]sidant\s+(?:au|à|a)|domicili[ée]e?\s+(?:au|à)|(?:con\s+)?domicilio\s+en|cuya\s+direcci[óo]n\s+(?:es|se\s+registra\s+en)|residente\s+(?:al\s+seguente\s+indirizzo|in|a)|woonachtig\s+(?:aan|te|op)|wonende\s+(?:aan|te|op)|wohnhaft\s+(?:in|an)|bosatt\s+(?:på|i)|med\s+adress(?:en)?|(?:à|a)\s+l['’]\s?adresse|all['’]\s?indirizzo|en\s+la\s+direcci[óo]n`;
/** Either case for a label's letters, without the i flag: under it \p{Lu} matches lower case too. */
const anyCase = (source: string) => {
  let out = "";
  let inClass = false;
  for (let i = 0; i < source.length; i++) {
    const c = source[i];
    if (c === "\\") { out += c + (source[i + 1] ?? ""); i++; continue; }
    if (c === "[") inClass = true;
    else if (c === "]") inClass = false;
    // Inside a class, add the capital beside the letter; outside, make one.
    // Any script's: ΑΦΜ, ИНН, IČO.
    const up = c.toUpperCase();
    if (up !== c && up.length === 1) out += inClass ? c + up : `[${c}${up}]`;
    else out += c;
  }
  return out;
};
const ADDRESS_WORD = String.raw`\p{Lu}[\p{L}'’.-]*`;
const ADDRESS_PARTICLE = String.raw`(?:de|del|della|delle|di|da|du|des|la|le|las|los|van|von|der|den|y|e)`;
const ADDRESS_LAST_LOWER = String.raw`\p{Ll}[\p{L}'’-]*(?=[ \t]*(?:[,;|<"')\]\r\n]|$))`;
const ADDRESS_UNIT = String.raw`(?:Apt|Apartment|Suite|Ste|Flat|Unit|Studio|Puerta|Piso|Lgh|Wohnung|Appartamento|Interno|Int)\.?`;
export const ADDRESS_LABELLED_PATTERN = new RegExp(
  // Up to two more words may qualify the label before its colon: "Indirizzo di
  // fatturazione:", "Adresse de facturation :", "Indirizzo mittente:".
  String.raw`(?:\b(?:${anyCase(ADDRESS_FIELD)})\b(?:[ \t]+[\p{L}'’]{2,20}){0,2}?(?:[ \t]*\([^)\n]{0,30}\))?["'\\]*[ \t]*(?:[:=>]|\*\*:?)[ \t*"']*|\b(?:${anyCase(ADDRESS_PHRASE)})[ \t]*:?[ \t]*["']?)` +
  "(" +
    // A building number first: "7463 Katrina Keys", "8/8 Röhrdanzgasse", "81 Pasadizo de Victoria Chico",
    // and a French or Italian street word in lower case after it: "27, avenue de Martins".
    String.raw`\d{1,5}(?:[/-]\d{1,4})?[A-Za-z]?,?[ \t]+(?:${ADDRESS_WORD}|(?:rue|avenue|boulevard|chemin|impasse|allée|place|quai|via|viale|vicolo|piazza|corso|strada|calle|avenida|paseo|camino|carrer|plaza)(?=[ \t]+\p{L}))(?:[ \t]+(?:${ADDRESS_WORD}|${ADDRESS_PARTICLE}(?=[ \t]+\p{L})|${ADDRESS_LAST_LOWER})){0,5}` +
      String.raw`(?:,[ \t]*${ADDRESS_UNIT}[ \t]*#?[A-Za-z]?\d{1,5}[A-Za-z]?\b)?` +
    // A unit first, then the street: "Flat 42, Mathew ridges", "Studio 9, Cheryl corners".
    // Before the name-first form, which would stop at "Studio 9".
    String.raw`|${ADDRESS_UNIT}[ \t]*\d{1,4}[A-Za-z]?,[ \t]*${ADDRESS_WORD}(?:[ \t]+(?:${ADDRESS_WORD}|${ADDRESS_LAST_LOWER})){0,3}` +
    // A name first and the number after: "Trudel-Lübs-Ring 6", "Contrada Paride, 7", "calle del Sol 10".
    String.raw`|(?:${ADDRESS_WORD}|calle|via|viale|vicolo|rue|avenue|avenida|strada|piazza|plaza|paseo|carrer|rua|chemin|place)(?:[ \t]+(?:${ADDRESS_WORD}|${ADDRESS_PARTICLE})){0,4},?[ \t]+\d{1,5}[A-Za-z]?(?![\p{L}\d.,:/-]*\d)` +
  ")",
  "gdu",
);
/** Labels that make "address" a machine's, not a person's. */
export const ADDRESS_LABEL_NOT_A_STREET = /\b(?:ip|ipv[46]|mac|e-?mail|web|wallet|memory|server|host|url|bitcoin|btc|eth(?:ereum)?|contract|return|base|load|physical\s+memory|bus|device|network|ethernet|hardware|broadcast)[\s_-]*$/i;

/** UK postcodes are a written-down grammar, which is why they can be matched
 *  on sight where a US ZIP cannot. */
/* Not inside base64: "+M79YN/" sat in an image pasted as text (oasst2). */
export const UK_POSTCODE_PATTERN =
  /(?<![#\w+-])(?:GIR ?0AA|[A-PR-UWYZ][A-HK-Y]?\d[A-Z\d]?\s*\d[ABD-HJLNP-UW-Z]{2}|[a-pr-uwyz][a-hk-y]?\d[a-z\d]? \d[abd-hjlnp-uw-z]{2})(?![\w-])(?!\+\w)/g;
/* The letters are Royal Mail's own rules, not just "one or two letters": no
   area starts with Q, V or X, the second letter is never I, J or Z, and the
   last two never use C, I, K, M, O or V. Microsoft Presidio's tests hold
   "QA1 1AA" and "M1 1CA" up as postcodes that cannot exist.
   Capitals, or lower case with the space: "sw1a 1aa" is typed that way, but
   "b67sr" is the end of a Kubernetes pod name and "#D5A6BD" is a colour. */

/**
 * Canada's is a grammar too — letter digit letter, space, digit letter digit,
 * with six letters never used in it.
 *
 * The space is required, and that is the whole of what makes this safe. Without
 * it the pattern is six alternating characters, which is also a product code, a
 * coupon and a serial number: "Model A1B2C3", "coupon H3X9K2" and "Serial
 * N4P7V2" were all being taken as postcodes, and a reader would then watch the
 * model reason confidently about a value they never wrote.
 *
 * The cost is "K1A0B1" written closed up, which goes through. That is the
 * trade this file makes everywhere else: a missed identifier over a mangled
 * answer.
 */
export const CA_POSTCODE_PATTERN = /\b[ABCEGHJ-NPRSTVXY]\d[ABCEGHJ-NPRSTV-Z][ ]\d[ABCEGHJ-NPRSTV-Z]\d\b/gi;

/**
 * A US ZIP, but only where it is unmistakably one: after a state code, or
 * after the word for what it is. Five bare digits is a year, a price, a
 * quantity and a room number far more often than it is a postcode, and
 * redacting all of those to protect the last one is a bad trade.
 */
export const US_ZIP_PATTERN =
  /\b[A-Z]{2}\s+(\d{5}(?:-\d{4})?)\b/gd;
/* The same ZIP after the word for what it is, case-insensitively — "Zip
   30301-1234" is how a person writes it and the case-sensitive pattern above
   only ever saw the lower-case form. Kept separate rather than adding an `i`
   flag to that one: with `i`, its two-letter state code matches any two-letter
   word, and "It cost 12000 dollars" becomes a redacted postcode. */
/**
 * ZIP+4, standing on its own.
 *
 * The pattern above wants a state or a cue in front of the number, because a
 * bare five digits is a quantity as often as it is a postcode and redacting
 * every one of them would take the year out of half the sentences on earth.
 * `12345-6789` is a different case: nine digits split five-and-four is a
 * shape almost nothing else has, so it carries its own evidence and needs no
 * state beside it.
 *
 * Worth 75 of the 135 postcodes in the public corpus, which writes addresses
 * as "Waters Harbors, 63399-1160" with no state anywhere near them.
 */
export const US_ZIP_PLUS4_PATTERN = /\b\d{5}-\d{4}\b/g;

/**
 * A five-digit ZIP sitting inside an address.
 *
 * A bare five digits cannot be redacted on its own — it is a year, a count,
 * a price, an order reference — which is why US_ZIP_PATTERN wants a state in
 * front of it. But "Suite 989, and 72206", "Apt. 881, 28802." and "at 64903,
 * Apt. 820" are all five digits standing next to an unmistakable piece of an
 * address, and the piece beside them is the evidence the state would have
 * been.
 *
 * Apt and Suite only, on either side, and a comma between. The same three
 * words that were not trusted to make an address on their own — see the note
 * where SECONDARY_ADDRESS_PATTERN is not — are perfectly good at saying that
 * the number beside them is a postcode.
 */
export const ZIP_BESIDE_ADDRESS_PATTERN =
  /(?:(?:Apt|Apartment|Suite|Ste)\.?\s*#?\s*[A-Za-z]?\d{1,6}[A-Za-z]?,?\s+(?:and\s+)?(\d{5})(?!-?\d)|(\d{5}),\s*(?:Apt|Apartment|Suite|Ste)\b)/gd;

/**
 * A postcode at the end of a place.
 *
 * "Fort Elyssaburgh, Glarus, 53752", "New Arianna, East of England, 55902" —
 * the five digits close an address and there is no state code in front of
 * them, because the corpus writes counties and regions rather than the two
 * letters US_ZIP_PATTERN wants.
 *
 * What stands in for the state is the shape of the sentence: a capitalised
 * place, a comma, the digits, and then the clause ends. "Total, 12345" fails
 * on the capital being a word anybody would write mid-sentence — which is
 * not much of a guard, so the clause ending is required too, and that is
 * what keeps "we ordered 12345 units, 400 of them blue" out.
 */
export const ZIP_AFTER_PLACE_PATTERN =
  /\b[A-Z][\p{L}'’-]+(?:\s+(?:of\s+)?[A-Z][\p{L}'’-]+){0,3},\s*(\d{5})(?=[.,?!;)\s]*$|[.?!])/gdu;

/**
 * An Australian postcode: four digits after the state. NSW, VIC, QLD and TAS
 * are only ever states; SA, WA, NT and ACT are also words and abbreviations,
 * so those need a capitalised place in front ("Adelaide SA 5000"). Either
 * way the clause has to end after the digits, or "NSW 2024 results" would
 * lose its year.
 */
export const AU_POSTCODE_PATTERN =
  /(?:\b(?:NSW|VIC|QLD|TAS)|(?<=\b[A-Z][a-z]+,?\s)(?:SA|WA|NT|ACT))\s+(\d{4})(?=\s*(?:$|[,.;)\n]|Australia))/gdu;

/**
 * A European street as it stands before its postcode: "Hauptstraße 5",
 * "Calle Mayor 12", "15 Rue du Faubourg". Used only as a lookbehind.
 *
 * "comma, four digits, capitalised word" alone was tried first and took
 * "In total, 1500 Americans" and "See Table 4, 2500 Respondents" — ordinary
 * sentences are full of that shape. The street in front is the evidence.
 */
const EU_STREET_BEFORE = [
  String.raw`[A-Z][\p{L}'’-]*(?:${STREET_SUFFIXES_WELDED})\s+\d{1,4}[a-z]?`,
  String.raw`(?:${STREET_PREFIXES})\s+(?:${STREET_PARTICLES})?[A-Z][\p{L}'’-]*(?:\s+[A-Z][\p{L}'’-]*)?(?:,?\s+\d{1,4}[a-z]?)?`,
].join("|");

/**
 * The floor and flat a European address puts between its street and its
 * postcode: "3º B", "2º izq.", "1ª dcha", "piso 4", "2. OG", "3e étage",
 * "Apt 4". Two at most, each with its comma.
 */
const EU_FLAT_PART = String.raw`(?:\d{1,2}\s*[º°ª]\s*(?:[A-Za-z]|izq(?:uierda)?\.?|dcha\.?|dch\.?|centro)?|(?:piso|planta|puerta|escalera|esc\.?|andar)\s+\w{1,4}|\d{1,2}\.\s*(?:OG|Stock|Etage|Obergeschoss)|\d{1,2}(?:e|er|ème)\s+étage|(?:Apt|Apto|Appt)\.?\s*\w{1,4})`;

/**
 * A continental postcode: "10115 Berlin", "75008 Paris", "28013 Madrid",
 * after a European street and its comma, and before a capitalised town.
 * The floor and flat may come between: "Calle Mayor 45, 3º B, 28013 Madrid".
 */
export const EU_POSTCODE_PATTERN = new RegExp(
  String.raw`(?<=(?:${EU_STREET_BEFORE})(?:,\s*${EU_FLAT_PART}){0,2}(?:[ 	]+[A-H][ 	]?\d{1,3})?(?:,|[ 	]+[·|•])\s*)(\d{4,5})(?=\s+[A-Z][\p{Ll}]+(?:[\s,.;)]|$))`, "gdu");

/** A Dutch postcode: "Kalverstraat 92, 1012 PH Amsterdam". Same anchor; the
 *  two letters are what make it Dutch. */
export const NL_POSTCODE_PATTERN = new RegExp(
  String.raw`(?<=(?:${EU_STREET_BEFORE}),\s*)([1-9]\d{3}\s?[A-Z]{2})(?=\s+[A-Z][\p{Ll}]+)`, "gdu");

/**
 * A postcode with its town glued on, as text copied out of a PDF arrives:
 * "1050-196Lisboa", "8911 ABLeeuwarden" (realistic5, 2026-10-31). Portugal's
 * four-hyphen-three and the Netherlands' four digits and two capitals, right
 * against a capitalised word with no space between. Ordinary text never
 * runs a number into a word like that; a pasted address does.
 */
export const POSTCODE_GLUED_PATTERN =
  /(?<![\p{L}\d-])(\d{4}-\d{3}|[1-9]\d{3}[ ]?(?!AD|BC|AM|PM|KB|MB|GB|TB|SA|SD|SS)[A-Z]{2})(?=\p{Lu}\p{Ll}{3,})/gu;

/** An Irish Eircode, taken only beside a place that says it is Irish: the
 *  routing key is three characters any code could open with. */
export const EIRCODE_PATTERN =
  /\b(?:Dublin(?:\s+\d{1,2})?|Cork|Galway|Limerick|Waterford|Ireland|Eircode:?)\s*,?\s*((?:[AC-FHKNPRTV-Y]\d{2}|D6W)\s?[0-9AC-FHKNPRTV-Y]{4})\b/gd;

/**
 * A card's security code. Three or four digits are nothing on their own; the
 * word in front is the whole of the evidence, and it is unambiguous.
 */
export const CVV_CUED_PATTERN = /\b(?:cvv2?|cvc2?|csc|card\s+security\s+code|security\s+code)["']?\s*(?:(?:code|number|no\.?|#|is|:|["'])\s*)*(\d{3,4})\b/gid;

/** A ZIP after a state code and a comma, as a CSV writes it: "Miami,FL,33145".
 *  Real state codes only, in capitals, with no space after the comma and the
 *  field ending after the digits — "CA, 12000 units" is a sentence. */
export const US_ZIP_AFTER_STATE_COMMA_PATTERN =
  /\b(?:AL|AK|AZ|AR|CA|CO|CT|DE|DC|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI|MN|MS|MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|PR|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY),(\d{5}(?:-\d{4})?)(?=[,\r\n]|$)/gd;

/**
 * A phone number with its label after it, as an address block writes it:
 * "082 490 1693-Office", "416 60 039 office", "(37) 788-063 Fax". The label
 * is the cue, the same evidence as one in front, read from the other side.
 * The label ends its phrase: "922-6512\tOffice chair" is a part number and a
 * product in a spreadsheet row, not a desk phone (bench/formats).
 */
export const PHONE_LABEL_AFTER_PATTERN =
  /(?<![\w+])(\+?\(?\d[\d ().-]{5,18}\d)(?=[ \t]*-?[ \t]*(?:office|fax|mobile|cell|home|work)\b(?![ \t]+[a-z]))/gid;

/**
 * A US military address: "PSC 0413, Box 8144", "Unit 1009 Box 0219",
 * "APO AA 42323". Nothing else is written in either shape.
 */
export const MILITARY_ADDRESS_PATTERN =
  /\b(?:(?:PSC|Unit|CMR)\s+\d{3,5},?\s+Box\s+\d{1,5}|(?:APO|FPO|DPO)\s+(?:AA|AE|AP)\s+\d{5})\b/gi;
/** The ship on the line above an FPO: "USNS Kjær\nFPO AP 41060". The prefix
 *  is the Navy's and Coast Guard's own, and the line under it proves it. */
export const MILITARY_SHIP_PATTERN =
  /\b(?:USNS|USNV|USS|USCGC)[ \t]+\p{Lu}[\p{L}\p{M}'’.-]*(?:[ \t]+\p{Lu}[\p{L}\p{M}'’.-]*){0,2}(?=[ \t]*,?[ \t]*\r?\n[ \t]*(?:APO|FPO|DPO)[ \t]+(?:AA|AE|AP)[ \t]+\d{5}\b)/gu;

/**
 * A postcode on the last line of an address block, after the country:
 * "Austria 25173", "South Africa 70651". The country is the cue, and the
 * line has to end after the digits, which is how an address ends and how a
 * sentence about a country rarely does.
 */
const COUNTRIES = [
  "Albania", "Andorra", "Argentina", "Australia", "Austria", "Belarus", "Belgium", "Bolivia", "Bosnia and Herzegovina",
  "Brazil", "Bulgaria", "Canada", "Chile", "China", "Colombia", "Costa Rica", "Croatia", "Cyprus", "Czech Republic",
  "Czechia", "Denmark", "Ecuador", "Egypt", "Estonia", "Finland", "France", "Germany", "Greece", "Hungary", "Iceland",
  "India", "Indonesia", "Ireland", "Israel", "Italy", "Japan", "Latvia", "Liechtenstein", "Lithuania", "Luxembourg",
  "Malaysia", "Malta", "Mexico", "Moldova", "Monaco", "Montenegro", "Netherlands", "New Zealand", "North Macedonia",
  "Norway", "Pakistan", "Paraguay", "Peru", "Philippines", "Poland", "Portugal", "Romania", "Russia", "San Marino",
  "Saudi Arabia", "Serbia", "Singapore", "Slovakia", "Slovenia", "South Africa", "South Korea", "Spain", "Sweden",
  "Switzerland", "Taiwan", "Thailand", "Turkey", "Ukraine", "United Kingdom", "United States", "Uruguay", "USA",
  "Venezuela", "Vietnam", "Tunisia", "Morocco", "Algeria", "Greenland", "Kenya", "Nigeria", "Ghana", "Jamaica",
  "Luxemburg", "Nepal", "Sri Lanka", "Bangladesh", "Argentine Republic",
].join("|");
/**
 * The rest of an address block, one piece at a time: after the street, a
 * comma or a line break, then a unit ("Suite 741"), a postcode, or a place
 * ("Öntésmajor", "Reno NV 89501", "Cyprus (Greek) 26933", "Velká Bukovina
 * u Decína"). A place is capitalised words and the small words between
 * them, never a lower-case run: "12 Baker Street Tomorrow I fly to France"
 * ends in a country, and "I fly to" is what stops it. Sticky: it is run
 * from where the street ended. findStructured keeps the pieces only up to the
 * last one that proves the block is an address — a postcode, a two-letter
 * region or a country — so "12 Baker Street, Tuesday" keeps its Tuesday.
 *
 * A piece ends at a comma, a line break or the end of the sentence (a
 * question counts: "send it to … Slovenia?"), or, after a number, at a space
 * before a capital: "Apt. 073 Bussum Netherlands" is written without commas
 * as often as with them. The terminal rule is what keeps that safe.
 */
/** The shapes a postcode takes on an address line, with a digit in each:
 *  "CH-2544", "AD100", "C1070AAM", "1234 AB", "ASCN 1ZZ", "742CU001",
 *  "9614303", "11936-12345". Only ever read after a street (the tail) or
 *  right above one (findStructured's head), never on its own. */
export const POSTCODE_TOKEN = String.raw`(?:[A-Z]{2}\d-\d{4}|[A-Z]{1,2}-\d{3,6}(?: \d{2}(?!\d))?|\d{2}-\d{3}(?!\d)|[A-Z]{1,4}\d[A-Z0-9]{1,7}|[A-Z]{2,4} \d[A-Z0-9]{1,3}|\d(?=[A-Z0-9]*[A-Z])[A-Z0-9]{3,8}|\d{3,7}(?:[ -]\d{2,5}| [A-Z]{2}(?![\p{L}\p{N}]))?)`;
const SMALL_PLACE_WORDS = "de|da|das|do|dos|des|di|du|del|della|delle|la|le|les|u|v|na|nad|pod|am|im|an|der|den|van|von|y|och|sur|en|sous|bei|ob|zu|ter";
/** A place: capitalised words, or words in a script without capitals
 *  (安徽省, أسوان, กระบี่, 강원), and the small words between them.
 *
 *  A full stop inside a word ("U.S.A.") or ending a short one ("St.
 *  Albans", "Mt. Pleasant"), never one that ends a sentence: "Fore Street,
 *  Exeter. GCS 13, BM 2.1" read "Exeter. GCS" as a town and "13" after it
 *  (2026-10-08). */
const PLACE_WORD = String.raw`[\p{Lu}\p{Lo}](?:[\p{L}\p{M}'’-]|\.(?=[\p{L}\p{M}])){0,30}(?:(?<![\p{L}\p{M}]{4})\.)?`;
const PLACE_WORDS = String.raw`${PLACE_WORD}(?:[ \t]+(?:${PLACE_WORD}|(?:${SMALL_PLACE_WORDS})(?=[ \t])|\(\p{L}{1,20}\))){0,4}`;
export const ADDRESS_TAIL_PATTERN = new RegExp(
  String.raw`(?:[ \t]*,[ \t]*(?:\r?\n[ \t]*)?|[ \t]*\r?\n[ \t]*,?[ \t]*|[ \t]+)(` +
    String.raw`(?:Apt|Apartment|Suite|Ste|Unit|Flat|Room|Floor|Fl)\.?[ \t]*#?[0-9A-Z]{1,5}` +
    String.raw`|${POSTCODE_TOKEN}(?:[ \t]*-?[ \t]*${PLACE_WORDS})?` +
    String.raw`|${PLACE_WORDS}(?:[ \t]*-?[ \t]*${POSTCODE_TOKEN})?` +
    String.raw`)(?=[ \t]*(?:[,\r\n]|$|[.;?!](?:\s|$))|(?<=\d)[ \t]+[\p{Lu}\p{Lo}]|(?<=\d{3})(?<!(?<!\d)(?:19|20)\d\d)[ \t]+\p{Ll})`,
  "uyd",
);
/** A capitalised name and a building number, either way round, which
 *  findStructured takes only when an address block follows it. */
export const STREET_BEFORE_BLOCK_PATTERN =
  /(?<![\p{L}\p{N}'’.\/-])(?:\d{1,5}[A-Za-z]?[ \t]+\p{Lu}[\p{L}\p{M}'’.-]{1,30}(?:[ \t]+(?:\p{Lu}[\p{L}\p{M}'’.-]{0,30}|de|da|do|di|du|del|la|le|van|von|der|den)){0,3}|\p{Lu}[\p{L}\p{M}'’.-]{1,30}(?:[ \t]+(?:\p{Lu}[\p{L}\p{M}'’.-]{0,30}|de|da|do|di|du|del|la|le|van|von|der|den)){0,3}[ \t]+\d{1,5}[A-Za-z]?\.?)(?=[ \t]*(?:,|\r?\n))/gud;
/**
 * A reply that is only a value: "560 1234", "it's 90210", "sure — X1234567".
 * The whole conversation is scanned one message a line, so the line before a
 * reply is the question it answers, and findStructured takes the value only
 * when that question asked for one: a phone number, a postcode, an ID. On
 * its own, "560 1234" is any number at all.
 */
export const BARE_REPLY_PATTERN =
  /^[ \t]*(?:(?:it'?s|its|it is|sure|yes|yeah|ok(?:ay)?|here you go|that'?s|my \w+(?: \w+)? is)[ \t,:—-]*)?([+(]?[\dA-Z][\dA-Z ().\/-]{2,22}[\dA-Z])[ \t]*[.!]?[ \t]*$/gimd;
export const ASKED_FOR_PHONE = /\b(?:phone|mobile|cell|telephone|contact number|number (?:to|where|we can) (?:reach|call|contact)|call you|reach you|text you)\b[^\n]*\?[ \t]*$/i;
export const ASKED_FOR_POSTCODE = /\b(?:zip(?: ?code)?|post ?code|postal code|pin ?code|plz)\b[^\n]*\?[ \t]*$/i;
export const ASKED_FOR_ID = /\b(?:ID|passport|licen[cs]e|social security|SSN|SIN|national insurance|NI number|NHS number|account number|member(?:ship)? (?:number|ID)|policy number|patient (?:number|ID)|tax (?:ID|number|file number)|TFN|Aadhaar|PAN|customer (?:number|ID)|reference number|registration number|date of birth|DOB)\b[^\n]*\?[ \t]*$/i;

export const ADDRESS_BLOCK_TERMINAL = new RegExp(String.raw`\d{3}|^\p{Lu}{2}$|(?:^|[ \t])(?:${COUNTRIES})$|(?:^|[ \t-])(?:[A-Z]{1,4}[ -]?\d[A-Z0-9]{1,7}|\d(?=[A-Z0-9]*[A-Z])[A-Z0-9]{3,8})(?:$|[ \t])`, "u");

/**
 * A postcode after the town it belongs to, in a sentence: "in København K
 * 1421", "in ÖVERTURINGEN 840 24", "in Quinta de São Tiago 3610-114". The
 * town has to be capitalised and the code has to end its phrase, so "in
 * Tokyo 1000 people" is a count; findStructured also refuses years and the
 * words in NOT_A_STREET ("in Chapter 1021", "in Version 4844"). Four digits
 * alone are every product's version number ("in Firefox 1150", "in Redis
 * 6379"), so they need a town of two words or one in capitals.
 */
export const PLACE_POSTCODE_PATTERN =
  /(?<=\bin[ \t])((?:\p{Lu}[\p{L}'’.-]{2,})(?:[ \t]+(?:\p{Lu}[\p{L}'’.-]*|de|da|do|di|del|la|le)){0,3})[ \t]+(\d{4,5}|\d{3} \d{2}|\d{4}-\d{3}|\d{2}-\d{3})(?=[ \t]*(?:[,;!?)\n]|\.(?:\s|$)|$|[ \t]+(?:in|and|or|for|to|with|on)\b))/gdu;

export const COUNTRY_POSTCODE_PATTERN = new RegExp(
  String.raw`\b(?:${COUNTRIES})\s+(\d{3,6}(?:[ -]\d{2,4})?)(?=[ \t]*[.?!]?[ \t]*(?:\r?\n|$))`, "gdm");

/**
 * A postcode the sentence names, in any country's format: "ZIP: 3520",
 * "postal code 53-320", "zip code is 394 13", "3610-114". US_ZIP_CUED_PATTERN
 * takes the American five digits; this takes the rest.
 */
export const POSTCODE_CUED_INTL_PATTERN =
  /\b(?:zip|zipcode|zip\s+code|postcode|post\s+code|postal\s+code|plz)\s*(?:is|:|#)?\s*(\d{2,5}(?:[ -]\d{2,4})?)(?![\d-])/gid;

/**
 * A postcode its label names, in any country's shape: "Postcode: ASCN 1ZZ",
 * "PLZ 1010", "CEP: 40301-110", "PIN code 110034", "Postal code 266033".
 * POSTCODE_CUED_INTL_PATTERN takes digits only; this also takes the letter
 * shapes (POSTCODE_TOKEN). No i flag on the value, so "postcode 1234 and"
 * cannot take "and": postcodes are written in capitals.
 */
export const POSTCODE_LABELLED_PATTERN = new RegExp(
  /* "is" was the only verb, so "Mi código postal es 28013", "Mon code postal
     est 75002", "Il mio CAP è 00184" and "Meine Postleitzahl ist 10115" all
     went out — found by the multilingual benchmark. Hindi and Telugu write
     "पिन कोड" and "పిన్ కోడ్", which `\b` cannot see the start of, so they
     stand outside it. */
  String.raw`(?:\b(?:[Pp]ost(?:al)?[ \t]*[Cc]ode|POST(?:AL)?[ \t]*CODE|[Zz]ip(?:[ \t]*[Cc]ode)?|ZIP(?:[ \t]*CODE)?|PLZ|[Pp]lz|[Pp]ostleitzahl|CEP|CAP|[Cc]odice[ \t]+[Pp]ostale|PIN[ \t]*[Cc]ode|[Pp]in[ \t]*[Cc]ode|[Pp]incode|[Cc][oó]digo[ \t]+[Pp]ostal|[Cc]ode[ \t]+[Pp]ostal|C\.?P\.?(?![\p{L}\p{N}])|[Cc][oó]d\.[ \t]*[Pp]ostal|POSTA[ \t]+KODU|[Pp]osta[ \t]+[Kk]odu|[Ii]r[áa]ny[íi]t[óo]sz[áa]m|[Kk]od[ \t]+[Pp]ocztowy|PS[ČC]|[Pp]ostnummer|[Pp]ostinumero)|पिन[ \t]*कोड|पिनकोड|పిన్[ \t]*కోడ్|מיקוד|우편번호|邮编|郵遞區號|郵便番号|〒)[ \t]*(?:(?:is|es|est|ist|è|lautet|है)[ \t]+|[:#：][ \t]*)?(${POSTCODE_TOKEN})(?![\p{L}\p{N}-])`,
  "gdu",
);
/**
 * A postcode label glued to whatever came before it, as a form copied flat
 * runs its fields together: "Κηφισίας 233ΤΚ:14561", "кв.201Индекс:420066",
 * "155 кв.32Індекс:79022", "ז׳בוטינסקי 15מיקוד:4910101", "No:3Posta
 * Kodu:35220", and India's "PIN"/"पिन"/"পিন" run into the six digits
 * (realistic6 and realistic7 misses, read 2026-11-11). POSTCODE_LABELLED_PATTERN
 * needs a word boundary before the label, which a glued label does not have;
 * this asks instead that the letter before is not of the label's own script,
 * and that the value is the label's country's length.
 */
export const POSTCODE_LABEL_GLUED_PATTERN = new RegExp(
  String.raw`(?:(?<![\p{Script=Greek}])Τ\.?Κ\.?|(?<![\p{Script=Cyrillic}])[ИиІі]ндекс|(?<![\p{Script=Hebrew}])מיקוד|(?<![\p{L}])(?:POSTA|[Pp]osta)[ \t]*(?:KODU|[Kk]odu))[ \t]*[:：]?[ \t]*(\d{3}[ ]?\d{2,4})(?!\d)` +
  String.raw`|(?<![\p{Script=Latin}\p{Script=Devanagari}\p{Script=Bengali}])(?:PIN|पिन|পিন)[ \t]*[:：]?[ \t]*(\d{6})(?!\d)`,
  "gdu",
);

/**
 * A postcode a few words after a street, past the flat and the floor, with
 * its town after it: "Hauptstraße 102, Whg. 5 70563 Stuttgart",
 * "Drottninggatan 5 lgh 1001 111 51 Stockholm", "Váci utca 10. 3/4, 1052
 * Budapest", "Keizersgracht 210-II, 1015 CX Amsterdam" (realistic6 misses,
 * read 2026-11-11). Read only on the line's next sixty characters after a
 * street findStructured has found: the street is the evidence, the
 * capitalised town the rest. Shapes: four digits and two capitals (the
 * Netherlands), three and two (Sweden, Czechia, Greece), five and three
 * (Brazil), or four to six digits.
 */
export const POSTCODE_AFTER_STREET_PATTERN =
  /^[^\n]{0,40}?[\s,](\d{4}[ ]?[A-Z]{2}|\d{3}[ ]\d{2}|\d{5}-\d{3}|\d{4,6})(?=[ \t]+\p{Lu}\p{Ll}{2,})/du;
/** Taiwan's postcode run into the city or county it belongs to: "110台北市", "40354台中市". */
export const TW_POSTCODE_BEFORE_CITY_PATTERN = /(?<![\d\p{Script=Latin}.,-])(\d{3}(?:\d{2,3})?)(?=(?![个個座多家的余餘])\p{Script=Han}{1,2}[市縣县])/gdu;
/** Korea's five digits in brackets after a road address: "동성로2길 18 (41939)", "302호 (03995)". */
export const KO_POSTCODE_AFTER_ADDRESS_PATTERN = /(?<=(?:[로길]|번길|대로)\s?\d{1,4}(?:-\d{1,4})?(?:,\s?\d{1,4}호)?\s?[(（])(\d{5})(?=[)）])/gdu;

/** A line that is a postcode, with or without its town: read only directly
 *  above a street findStructured has already found ("125075 Springfield"
 *  over "12 Station Road", the way Russia and its neighbours write it). */
export const POSTCODE_LINE_PATTERN = new RegExp(String.raw`^[ \t]*(${POSTCODE_TOKEN})(?:[ \t]*-?[ \t]*${PLACE_WORDS})?[ \t]*,?[ \t]*$`, "u");
export const PLACE_LINE_PATTERN = new RegExp(String.raw`^[ \t]*${PLACE_WORDS}[ \t]*,?[ \t]*$`, "u");

export const US_ZIP_CUED_PATTERN =
  /\b(?:zip|zipcode|zip code|postcode|postal code)\s*:?\s*(\d{5}(?:-\d{4})?)\b/gid;

/**
 * Numbers that only a cue identifies. The value is whatever follows the cue:
 * at least six characters of letters, digits, spaces and hyphens, which is
 * short enough to catch a licence and long enough not to run into the rest of
 * the sentence.
 */
/**
 * A domestic account number, which only the word in front of it identifies.
 *
 * IBAN carries its own country code and check digits, so it is found by
 * shape. A UK or US account number is eight or ten digits and nothing else —
 * the same shape as an order number, a reference, a part code — so there is
 * no honest way to find one on its own, and this engine does not try.
 *
 * What it can do is read the cue. "your account 71573733", "made from our
 * bank account 25038585", "Loan Account - Number: 20227980": the word is
 * right there, and it was worth 175 of the 229 account numbers in the public
 * corpus, every one of which went to the model in the clear.
 *
 * The gap between the cue and the digits is deliberately narrow — a comma, a
 * dash, a bracket, and a handful of joining words. "account balance 4500"
 * does not match, because "balance" is not one of them, and that is the whole
 * guard.
 *
 * The joining words grew once, from the misses in the practice set: "Savings
 * Account with the number 63149872", "Account numbered 54122073", "account
 * number affiliated to it is 82172872", "acct 67625178". "with", "under" and
 * "numbered" also join a count to its noun — "an account with 250000 seats" —
 * so after them the number must be eight digits or more, and a count word
 * straight after the number ("25000000 users") calls it off everywhere.
 *
 * "sort code", "transfer" and "funds to" are here for the same reason the
 * word "account" is: each one names the number after it. BIC and SWIFT were
 * tried too, as cues for the account number, and moved nothing on the corpus,
 * so they are not here. The BIC itself is found by BIC_CUED_PATTERN.
 *
 * `X{4,}` is there because a statement writes "number finishes with
 * XXXXXX07133007": the masking is the bank's, the digits after it are still
 * the account, and a pattern that stops at the Xs leaves them in the clear.
 *
 * Reported as `iban`: it is the bank-account bucket, which is what a policy
 * blocking bank details is written against and what the site calls "Bank
 * accounts". A kind of its own would mean a new entry in the shared
 * vocabulary, which every policy editor and SDK reads.
 */
/*
 * There is no SECONDARY_ADDRESS_PATTERN, and that is a decision rather than
 * an omission.
 *
 * "Apt. 259" and "Suite 786" are 143 of the public corpus's address values
 * and the single biggest thing this engine misses. A pattern for them is
 * four lines and takes the corpus from 56% to 68%.
 *
 * It also redacts "Suite 300, second floor." — which redaction.eval and
 * scanner-safety both already assert must be left alone, on the grounds that
 * a suite number with no street attached identifies nobody. 166 of 5,000
 * ordinary sentences went with it.
 *
 * That rule predates this file's benchmark and it is the right one: a flat
 * number on its own is not personal data, and the corpus labels it only
 * because it sits beside an address in a generated document. Changing it
 * would be a product decision about what counts as identifying, not a
 * detection improvement, so the pattern is not here.
 */

/**
 * A phone number the sentence names.
 *
 * See the note at the scan for why this is cued rather than shaped.
 *
 * Chinese writes the label straight against the number, often with 是 ("is"):
 * "我的电话是139 1076 4823", "手机186-2153-0947", "手機號碼：0912-345-678".
 */
export const PHONE_CUED_PATTERN =
  /(?:\b(?:my|his|her|their|our|your)\s+(?:[A-Za-z]+\s+){0,2}number(?:\s+is)?|(?<=^|\n)[ \t]*(?:T|M|P|C|Ph|Mob|Cel|Tlf|Tfn|Tél|Telf|Móvil|Handy)\.?(?=[ \t]*[:：])|電話(?:番号)?|携帯(?:番号)?|(?:联系)?电话(?:号码)?是?|手[机機](?:号码?|號碼?)?是?|電話號碼是?|\b(?:phone|tel|telephone|mobile|cell|fax|contact(?:\s+(?:me|us|him|her|them))?(?:\s+(?:at|on))?|call(?:\s+(?:me|us|him|her|them))?(?:\s+(?:at|on))?|reach(?:\s+(?:out|me|us|him|her|them))*(?:\s+(?:at|on|via))?|reach(?:ed|able)\s+(?:at|on|via)|get\s+in\s+touch(?:\s+(?:at|on|via))?|queries\s+to|enquiries\s+to|answering\s+at|messages?\s+to|registered(?:\s+(?:number|mobile|phone))?|text(?:\s+(?:me|us))?(?:\s+(?:at|on))|whats\s?app|sms|dial))\s*(?:via|through|using)?\s*(?:number|no\.?|#|is)?\s*[:：\-]?\s*(\+?[\d(][\d\s().\-]{6,19}\d)(?!(?<=[ \t]\d{1,3})(?:[A-Za-z\d]|\/\d))/gid;

/**
 * The short national numbers of small places — Tokelau's "7290", Andorra's
 * "312 345", Tuvalu's "90 1234" — after a request to call. Four to six
 * digits is the shape of a lot of things, so only "call/ring/phone/text me
 * on/at", and only where the number ends the phrase; findStructured refuses
 * a time ("call me at 1030 tonight").
 */
/**
 * A Brazilian or Portuguese account with its check digit: "conta 63049-8",
 * "conta corrente nº 0123456-X", "c/c 12345-6". The hyphen and the one
 * digit after it are what make it an account (leak hunt, 2026-11-14).
 */
export const PT_ACCOUNT_PATTERN = /(?<![\p{L}])(?:conta(?:\s+corrente|\s+poupan[çc]a)?|c\/c)\s*(?:n[º°.]?\s*)?[:#]?\s*(\d{4,12}-[\dXx])(?![\d\p{L}])/giud;

export const PHONE_SHORT_CUED_PATTERN =
  /\b(?:[Cc]all|[Rr]ing|[Pp]hone|[Tt]ext|[Dd]ial)\s+(?:me|us|him|her|them)\s+(on|at)\s+(\d(?:[ .]?\d){3,6})(?=\s*(?:[.,;!?]|$|\s+(?:tonight|today|tomorrow|now|anytime|or|and|after|before|from)\b))/gd;

/**
 * A Social Security number the sentence names.
 *
 * SSN_PATTERN knows the dashed American shape. The corpus also writes
 * "SSN 756.9972.1808", "social security number 75629804811" and
 * "SSN: 756.9157.7022" — dots, no separator at all, and lengths that are not
 * American. None of those can be found by shape without redacting every
 * long number in every document; all of them are unmistakable once the words
 * in front are read.
 */
export const SSN_CUED_LOOSE_PATTERN =
  /\b(?:ssn|social\s+security(?:\s+(?:number|no\.?))?)\s*(?:number|no\.?|#|is)?\s*[:\-(]?\s*(\d[\d .\-]{6,16}\d)\b/gid;

/**
 * The same in French, Spanish and Portuguese: "Mon numéro de sécurité
 * sociale est 2 84 05 75 123 456 78", "número de la seguridad social:
 * 28 1234567840", "número de segurança social 12345678901".
 *
 * FR_NIR_PATTERN finds a French number by its shape and its mod-97 key, and
 * refuses one whose key is wrong, which is right for a number standing alone.
 * People mistype keys, though, and a number the sentence calls their social
 * security number is theirs whether its key adds up or not. So after one of
 * these labels the label is the evidence: nine to fifteen digits, grouped
 * however they are written, a few words between label and number at most.
 */
export const SSN_CUED_INTL_PATTERN =
  /(?<![\p{L}])(?:num[ée]ro\s+de\s+s[ée]curit[ée]\s+sociale|n[°º]\s*(?:de\s+)?s[ée]curit[ée]\s+sociale|n[úu]mero\s+de\s+(?:la\s+)?seguridad\s+social|n[úu]mero\s+de\s+afiliaci[óo]n|n[úu]mero\s+de\s+seguran[çc]a\s+social)(?![\p{L}])[^\n\d]{0,20}?(?<!\d)(\d(?:[ .-]?\d){8,16})(?!\d)/giud;

/**
 * A Swiss social security number, which has a shape after all.
 *
 * `756.9972.1808` — the 756 prefix is Switzerland's country code in the
 * EU standard and every AHV number carries it, then four and four. Nothing
 * else is written that way, so this one needs no cue: the corpus has a
 * couple of dozen sitting in sentences that never name them.
 *
 * The full number ends in two more digits, 756.9217.0769.85, and those are
 * taken with the rest when they are there. With dashes, only the full
 * number, "756-9380-5344-72" (open-pii-masking practice half, 2026-11-02):
 * three dashed groups alone could be some other code.
 */
export const CH_SSN_PATTERN = /\b756(?:[. ]\d{4}[. ]\d{4}(?:[. ]\d{2})?|-\d{4}-\d{4}-\d{2})\b/g;

/**
 * The same written as one run, "75629804811" or the full "7569217076985",
 * standing alone. Above, a run like this was thought to need the words in
 * front; but 756 and eight digits or ten is one long number in a thousand,
 * and every one of the 78 SSNs still missed on the ai4privacy practice half
 * was this shape in a sentence that never named it (2026-10-31). Not welded
 * to a word, a path, a decimal or an amount; a German compound after a dash
 * is fine, "eine 7569204673808-Nummer".
 */
export const CH_SSN_BARE_PATTERN = /(?<![\p{L}\p{N}_.,:\/#=+\-@$€£¥])756\d{8}(?:\d{2})?(?![\p{L}\p{N}_\/%]|-(?!\p{Lu}\p{Ll})|[.,]\d)/gu;

/**
 * An American Social Security number written with spaces.
 *
 * SSN_PATTERN knows "123-45-6789". "973 78 7767" is the same number with the
 * same three-two-four grouping and no hyphens, and it is how a fifth of the
 * corpus writes them. Nothing else is grouped that way — a phone number is
 * three-three-four, a date is not nine digits — so the grouping is the
 * evidence and no cue is needed.
 */
export const SSN_SPACED_PATTERN = /\b\d{3} \d{2} \d{4}\b/g;

/**
 * An IBAN by shape, with the checksum only as a preference.
 *
 * IBAN_PATTERN requires mod-97, and that is right for the ordinary case: two
 * letters followed by a run of characters is a shape a lot of things have.
 *
 * But a *long* one is not. Two letters, two digits, then fifteen to thirty
 * more characters with digits mixed through them is an international bank
 * account and essentially nothing else — no word is written that way, and a
 * product code or a serial that long would be a coincidence worth the false
 * positive. The corpus has six of these sitting in sentences that never say
 * the word IBAN and whose check digits a generator got wrong.
 *
 * Scanned last of the bank patterns, so a valid IBAN and a cued one are both
 * claimed by something stricter first.
 *
 * The country code has to be a real one. Without that list this matched
 * "HB4846180675X1152333X82307X" — an internal reference in a real Enron
 * email, and there were thousands of that shape. Two arbitrary capitals in
 * front of a long code is the commonest way a company numbers its own
 * documents, so "two letters, two digits, then a long run" is not on its own
 * a bank account at all.
 */
const IBAN_COUNTRIES =
  "AD|AE|AL|AT|AZ|BA|BE|BG|BH|BR|BY|CH|CR|CY|CZ|DE|DK|DO|EE|EG|ES|FI|FO|FR|GB|GE|GI|GL|GR|GT|HR|HU|IE|IL|IQ|IS|IT|JO|KW|KZ|LB|LC|LI|LT|LU|LV|LY|MC|MD|ME|MK|MR|MT|MU|NL|NO|PK|PL|PS|PT|QA|RO|RS|RU|SA|SC|SD|SE|SI|SK|SM|SO|ST|SV|TL|TN|TR|UA|VA|VG|XK";

/**
 * How long each country's IBAN is, from the SWIFT IBAN registry. With
 * mod-97 this is what lets an IBAN be found however it is spaced: "NO 0571
 * 3905 25162", "NO07.8380.08.06006", "ES72 2013-0692-81-0201150993". A run
 * of the wrong length for its country is not one, whatever its checksum.
 */
export const IBAN_LENGTHS: Record<string, number> = {
  AD: 24, AE: 23, AL: 28, AT: 20, AZ: 28, BA: 20, BE: 16, BG: 22, BH: 22, BR: 29, BY: 28, CH: 21, CR: 22,
  CY: 28, CZ: 24, DE: 22, DK: 18, DO: 28, EE: 20, EG: 29, ES: 24, FI: 18, FO: 18, FR: 27, GB: 22, GE: 22,
  GI: 23, GL: 18, GR: 27, GT: 28, HR: 21, HU: 28, IE: 22, IL: 23, IQ: 23, IS: 26, IT: 27, JO: 30, KW: 30,
  KZ: 20, LB: 28, LC: 32, LI: 21, LT: 20, LU: 20, LV: 21, LY: 25, MC: 27, MD: 24, ME: 22, MK: 19, MR: 27,
  MT: 31, MU: 30, NL: 18, NO: 15, PK: 24, PL: 28, PS: 29, PT: 25, QA: 29, RO: 24, RS: 22, RU: 33, SA: 24,
  SC: 31, SD: 18, SE: 24, SI: 19, SK: 24, SM: 27, SO: 23, ST: 25, SV: 28, TL: 23, TN: 24, TR: 26, UA: 29,
  VA: 22, VG: 24, XK: 20,
};
/** Where an IBAN may start: its country and check digits, with or without a
 *  space between them, and never a dot: "PO NO. 12…" is an order. */
export const IBAN_START_PATTERN = new RegExp(String.raw`(?<![A-Za-z0-9.\-])(${IBAN_COUNTRIES}) ?\d{2}`, "g");

export const IBAN_SHAPED_PATTERN = new RegExp(
  String.raw`\b(?:${IBAN_COUNTRIES})\d{2}(?=[A-Z0-9]*\d)(?=[A-Z0-9]*[A-Z])[A-Z0-9]{15,30}\b`,
  "g",
);

/**
 * An IBAN the sentence names, whose check digits do not add up.
 *
 * IBAN_PATTERN requires mod-97, which is right: two letters and a run of
 * characters is otherwise a very common shape. But when the text says
 * "IBAN: LV24JKIJ153849K88Y23J", the sentence has already told us what the
 * string is, and refusing it because a generator got the checksum wrong
 * sends a bank account to the model to make a point about arithmetic.
 *
 * Scanned after the checked form, so a valid IBAN is still claimed by its
 * own shape first.
 */
export const IBAN_CUED_PATTERN =
  /\b(?:iban)\s*(?:number|no\.?|#|is)?\s*:?\s*([A-Z]{2}\d{2}[A-Z0-9]{8,30})\b/gid;

/**
 * A card number its label vouches for, whether or not Luhn agrees.
 *
 * Read off a blurry photo, "4539 1488 0343 6467" came back "4539 4488 0343
 * 6467": one digit wrong, the check digit fails, and the card patterns —
 * which rely on Luhn to tell a card from an order number — let it go. The
 * picture then went up with the real number in its pixels. After "card on
 * file", "Visa", "Mastercard" and the like, the label says what the number
 * is, so 13 to 19 digits in card groups are taken as they are.
 */
export const CARD_LABELLED_PATTERN =
  /\b(?:card(?:\s+(?:on\s+file|number|no\.?|#))?|visa|master\s?card|amex|american\s+express|discover|maestro|debit\s+card|credit\s+card)\b\s*(?:(?:no\.?|number|#|ending\s+in)\s*)?[:#]?\s*(\d{4}(?:[ -]?\d{4}){2}[ -]?\d{1,7})\b/gid;

/**
 * A card number a few words after "credit card", "debit card" or "credit
 * debit card": "the credit debit card, 5187 3495 6702 1239, to purchase",
 * "**Credit/Debit Card:** 4929 1187 2815 7394", "her credit debit card,
 * number 3472 280123 45678", "CreditDebitCard": "3428 231567 19233".
 * CARD_LABELLED_PATTERN wants the number straight after the label and in
 * groups of four; Nemotron's practice rows (2026-10-08) wrote 29 of these
 * another way, half of them in American Express's 4-6-5. Up to forty
 * characters between, none a digit or a line break, and the number in a
 * card's own grouping (4-4-4-4, 4-6-5, 4-6-4) or one unbroken run.
 */
export const CARD_NEAR_LABEL_PATTERN =
  /\b(?:credit|debit)(?:[ \t_\/*-]{0,3}(?:or[ \t]{1,3})?(?:credit|debit))?[ \t_\/*-]{0,3}card\b[^\n\d$£€]{0,40}?(?<![\d.])(\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{4}(?:[ -]\d{1,3})?|\d{4}[ -]\d{6}[ -]\d{4,5}|\d{13,19})(?![\d-]|\.\d)/gid;

/**
 * A card number under its label in the benchmark's languages: "Numéro de
 * carte de crédit : 3014 5455 3834 7", "Número de tarjeta: 3747-4818-5090-405",
 * "Kredietkaartnummer: 3745-5158-7995-126", "10-CardNumber: 3736-0598-0536-908",
 * "Your credit card number is **060446905006**". CARD_LABELLED_PATTERN has the
 * English words and groups of four; this has the rest, twelve to nineteen
 * digits, a few words allowed between (never a digit or a line break).
 */
export const CARD_LABELLED_INTL_PATTERN =
  /\b(?:num[ée]ro\s+de\s+(?:la\s+)?carte(?:\s+(?:de\s+cr[ée]dit|bancaire|de\s+paiement))?|n[úu]mero\s+de\s+(?:la\s+)?tarjeta(?:\s+de\s+(?:cr[ée]dito|d[ée]bito))?|numero\s+(?:di\s+|della\s+)?carta(?:\s+di\s+(?:credito|debito))?|(?:kredit)?kartennummer|creditcardnummer|kredietkaartnummer|kaartnummer|cardnummer|(?:kredit)?kortsnummer|kortnummer|card[\s_\\-]*number|cardnumber|credit[\s_\\-]*card[\s_\\-]*(?:number|no\.?|num))\b(?:[^\n\d]{0,20}?)(?<!\d)(\d{4}(?:[ -]?\d{1,6}){1,4})(?![\d-])/gid;

/**
 * A card in four groups of four after the word for a card in the other
 * scripts and languages: "카드 9410 2271 6638 4010 결제가 실패했어요"
 * (realistic5, where it failed its check digit and went out). The groups are
 * the evidence the check digit would have been.
 */
export const CARD_LABELLED_WORLD_PATTERN =
  /(?:카드|カード|卡号|卡號|银行卡|信用卡|بطاقة|כרטיס|карта|карты|карту|картка|картки|kart[ıi]|karta|karty|kartu|kad|th[ẻe]|บัตร|कार्ड|কার্ড|κάρτα|κάρτας|k[áa]rtya|tarjeta|cart[ãa]o|carta|carte|kaart|kort|karte)(?![\p{L}])[^\n\d]{0,15}?(?<!\d)(\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{4})(?![\d-])/gdiu;

/**
 * The same written as one run of thirteen to nineteen digits, after the word
 * for a credit or bank card, whose number may follow it at once: "使用信用卡
 * 3110689241280584836 支付", "신용카드(502055795127082)", "(Cartão:
 * 373870243626801)" (moreLanguages practice half, 2026-11-02). Only the
 * words that mean a payment card: "카드" alone is a card of any kind.
 */
export const CARD_WORD_RUN_PATTERN =
  /(?<![\p{Script=Latin}])(?:信用卡|银行卡|借记卡|卡号|卡號|クレジットカード|デビットカード|カード番号|신용카드|체크카드|카드번호|cart[ãa]o(?:\s+de\s+(?:cr[ée]dito|d[ée]bito))?|tarjeta(?:\s+de\s+(?:cr[ée]dito|d[ée]bito))?)(?:号码|號碼|号|番号|번호)?(?![\p{Script=Latin}])[^\n\d]{0,12}?(?<!\d)(\d{13,19})(?!\d)/gdiu;

/**
 * A National Insurance number in the shape the UK writes it — two letters,
 * six digits, a letter — under a social-security label in any of the
 * benchmark's languages: "SSN: ZZ 883165 T", "Numero di previdenza sociale:
 * ZZ873084T", "the social security number ZZ 04 32 56 T". UK_NINO_PATTERN
 * takes the valid prefixes without a label; with one, neither the prefix nor
 * the final letter is checked, because "ZZ … T" is what forms and test data use.
 * The label in either case, the value in capitals — hence anyCase, not the i flag.
 */
export const NINO_CUED_PATTERN = new RegExp(
  String.raw`\b(?:${anyCase(String.raw`ssn|social\s+security(?:\s+(?:number|no\.?))?|national\s+insurance(?:\s+(?:number|no\.?))?|ni\s+(?:number|no\.?)|nino|(?:numero\s+di\s+)?previdenza\s+sociale|sozialversicherungsnummer|num[ée]ro\s+de\s+s[ée]curit[ée]\s+sociale|n[úu]mero\s+de\s+(?:la\s+)?seguridad\s+social|n[úu]mero\s+de\s+seguro\s+social|sociale?[\s-]+(?:veiligheids|zekerheids)nummer|socialf[öo]rs[äa]kringsnummer`)})\b(?:[^\n\d]{0,25}?)(?<![A-Za-z0-9])([A-Z]{2}[ ]?\d{2}[ ]?\d{2}[ ]?\d{2}[ ]?[A-Z])(?![A-Za-z0-9])`,
  "gd",
);

/**
 * A phone number under its label or its verb in the benchmark's languages:
 * "Telefon: 070-123 45 67", "Telefoonnummer: 088 - 1234567", "Téléphone :
 * 01 23 45 67 89", "door ons te bellen op 02 40 84 27 51", "contactez notre
 * service clientèle au 01 23 45 67 89", "Cust_Phone_Number": "0206-670 24".
 * PHONE_CUED_PATTERN has the English.
 *
 * "Tel." ends in a dot, and there is no word boundary between a dot and the
 * space after it, so until 2026-10-23 "Tel. 0151 23847561" was never taken
 * (found by the second realistic hold-out). The label may end at a boundary
 * or at its dot.
 */
export const PHONE_CUED_INTL_PATTERN =
  /(?:\b(?:telefon(?:nummer)?|telefoon(?:nummer)?|t[ée]l[ée]phone|t[ée]l\.|tel[ée]fono|cellulare|m[óo]vil|mobil(?:nummer|telefon)?|handy(?:nummer)?|gsm|portable|natel|mobilnummer|[\w]*phone[\s_]*number|numero\s+di\s+telefono|n[úu]mero\s+de\s+tel[ée]fono|num[ée]ro\s+de\s+t[ée]l[ée]phone)(?:\b|(?<=\.))["']?(?:\s*(?:[:=,]|(?:est|ist|is|es|è|lautet|är)(?![\p{L}\d])))*\s*["']?|\b(?:bellen\s+op|appeler\s+au|(?:contactez|joindre|appelez)(?:[ \t]+[\p{L}'’]+){0,4}?[ \t]+au|llam(?:ar(?:nos)?|e)\s+al|chiam(?:are|ateci)\s+(?:il|al)|ringa\s+(?:oss\s+)?på|anrufen\s+unter|unter\s+der\s+(?:rufnummer|nummer|telefonnummer))[ \t]+)(\+?\(?\d[\d ()./-]{5,18}\d)/giud;

/**
 * A phone number under its label in Hindi or Telugu: "मेरा फोन नंबर 98765
 * 43210 है", "मोबाइल नंबर: 98765-43210", "నా ఫోన్ నంబర్ 98765 43210",
 * "టెలిఫోన్ నంబర్ 0122 64 733 3627". Neither script has word boundaries
 * `\b` can see, so the labels are matched as written; the number is the same
 * as PHONE_CUED_INTL_PATTERN's. Found by the multilingual benchmark, where no
 * phone number written after a Hindi or Telugu label was caught.
 */
export const PHONE_CUED_INDIC_PATTERN =
  /(?:(?:फ़?ोन|मोबाइल|टेलीफ़?ोन|दूरभाष|संपर्क)\s*(?:नंबर|नम्बर|संख्या|न\.)?|(?:ఫోన్|మొబైల్|టెలిఫోన్|సెల్)\s*(?:నంబర్|నెంబర్|నంబరు|సంఖ్య)?)\s*(?:[:：\-]|है|ఇది)?\s*(\+?\(?\d[\d ()./-]{5,18}\d)/gdu;

/**
 * An identity number under its label in Hindi or Telugu: Aadhaar, PAN,
 * passport, driving licence, voter and identity cards. "आधार कार्ड संख्या
 * 1234 5678 9012", "मेरा पैन नंबर ABCDE1234F है", "పాస్‌పోర్ట్ నంబర్ K1234567".
 * The value needs a digit; spaces only inside a run of digits, which is how an
 * Aadhaar number is printed. The zero-width joiners Telugu is written with are
 * already gone from the text the patterns read (foldForScan).
 */
export const ID_CUED_INDIC_PATTERN =
  /(?:(?:आधार|पैन|पासपोर्ट|ड्राइविंग\s*लाइसेंस|मतदाता\s*(?:पहचान\s*पत्र|आईडी)|वोटर\s*आईडी|पहचान\s*पत्र|पहचान)(?:\s*(?:कार्ड|पत्र))?(?:\s*(?:संख्या|नंबर|नम्बर))?|(?:ఆధార్|పాన్|పాస్పోర్ట్|డ్రైవింగ్\s*లైసెన్స్|ఓటరు\s*(?:ఐడి|గుర్తింపు\s*కార్డు)|గుర్తింపు)(?:\s*కార్డు)?(?:\s*(?:సంఖ్య|నంబర్|నెంబర్|నంబరు))?)\s*(?:[:：\-]|है|ఇది)?\s*(?=[A-Za-z0-9 -]*\d)([A-Za-z0-9](?:[A-Za-z0-9-]|[ ](?=\d)){4,18}[A-Za-z0-9])(?![A-Za-z0-9])/gdu;

/**
 * A twelve-digit card its label vouches for: Maestro issues them, and the
 * card patterns start at thirteen because twelve bare digits is an order
 * number as often as anything. Only right after "card", "cc", "credit card"
 * or "debit card" (with "no", "#", "number is" allowed between), only twelve
 * digits standing alone, and findStructured still asks Luhn.
 */
export const CARD_TWELVE_CUED_PATTERN =
  /\b(?:card|cc|credit\s+card|debit\s+card)\b[.:]?\s*(?:(?:no\.?|number(?:\s+is)?|#)\s*[:#]?\s*)?(\d{12})(?![\d-])/gid;

export const ACCOUNT_CUED_PATTERN =
  /\b(?:(?:bank|loan|savings|saving|checking|current|deposit|investment|trading|merchant)?\s*accounts?(?:['’]s)?|acct\.?|acc\.?(?![a-z])|a\/c|sort\s+code|routing(?:\s+(?:and\s+)?transit)?(?:\s+number)?|aba(?:\s+number)?|bsb|transfer(?:red)?(?:\s+(?:to|from))?|funds\s+to)\s*(?:\(|-|–|,|&)?\s*(?:(?:no\.?|numbers?|num)\s+(?:ending|ends|finishes)\s+(?:in|with)|(?:numbers?|no\.?|details)\b[^.\n\d]{0,40}?\b(?:is|are)|(?:with|under|numbered|carrying|registered\s+with|identified\s+(?:with|by))(?:\s+(?:the|a))?(?:\s+(?:number|no\.?|#))?(?=\s*[-:#]?\s*(?:X{4,}\s*)?\d{8})|no\.?|numbers?|num|#|id|is|and(?:\s+number)?|&|ending(?:\s+(?:in|with))?|ends\s+(?:in|with)|finishes\s+with)?\s*[-–:,(]?\s*(?:X{4,}\s*)?(\d[\d -]{5,19}\d)\b(?:\s*(?:and|&|,)\s*(\d[\d -]{5,19}\d)\b)?(?!\s+(?:users?|requests?|points?|rows?|records?|items?|customers?|members?|transactions?|calls?|messages?|visits?|views?|followers?|subscribers?|units?|tokens?|credits?(?!\s+cards?)|miles?|times?)\b)/gid;

/**
 * A BIC its label vouches for: "BIC: UHKWFIXMXXX", "SWIFT code DEUTDEFF".
 *
 * Eight or eleven capitals is a shape that plenty of ordinary words and
 * constants share, so the code is never taken on its own — only straight
 * after "BIC" or "SWIFT", with at most "code", "number" and "is" between.
 * "Swift" alone is a programming language and needs "code" or "number" after
 * it before it counts. Case-sensitive in the code itself: a BIC is written in
 * capitals, and "BIC is required" is a sentence.
 *
 * Reported under the bank-account kind, beside the IBAN it usually travels
 * with, so a policy that blocks bank details blocks both halves.
 */
export const BIC_CUED_PATTERN =
  /(?:\b(?:BIC|[Bb]ic|SWIFT)\b|\b[Ss](?:wift|WIFT)(?=\s+(?:[Cc]ode|[Nn]umber)))(?:\s+(?:[Cc]ode|CODE|[Nn]umber|NUMBER|[Nn]o\.?))?(?:\s+(?:is|IS))?\s*[:(]?\s*\b([A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b/gd;

/** ISO 3166-1 alpha-2: the fifth and sixth letters of every real BIC. */
export const ISO_COUNTRY_CODES = new Set((
  "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ " +
  "CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR " +
  "GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP " +
  "KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT " +
  "MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW " +
  "SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG " +
  "UM US UY UZ VA VC VE VG VI VN VU WF WS XK YE YT ZA ZM ZW"
).split(" "));

/**
 * A BIC under the longer labels business paperwork gives it: "Swift BIC-code:
 * MQOIUSOH336", "il codice Swift BIC della Società è NHEVUSGV916",
 * "swift_bic_code of ASMIUSJO104", `scheme="http://www.swift.org/bic">`,
 * ":BANK_SWFT:". BIC_CUED_PATTERN only allows "code", "number" and "is"
 * between label and code; these allow a short run of lower-case words
 * (never a full stop or a line break) because the label is specific enough
 * to carry it. The code itself stays case-sensitive, and the scan checks its
 * fifth and sixth letters are a real country, so a capitalised word of the
 * same length in between ("Società") is passed over.
 */
export const BIC_LABELLED_PATTERN =
  /(?:\b[Ss](?:wift|WIFT)[\s_\\-]*(?:BIC|[Bb]ic)(?:[\s_\\-]*(?:[Cc]ode|CODE))?|\b(?:BIC|[Bb]ic)[\s_-]*(?:[Cc]ode|CODE)|\bswift\.org\/bic["']?>?|\bBANK_SWFT\b|\b(?:[Cc]odice|[Cc][óo]digo|[Cc]ode)\s+(?:SWIFT|[Ss]wift)|\b[Ss]wift(?:BIC|_?[Cc]ode)\b)[^\n.0-9]{0,60}?(?<![A-Za-z0-9])([A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)(?![A-Za-z0-9])/gd;

/**
 * A card security code under the labels CVV_CUED_PATTERN does not know —
 * the other six languages of the benchmark, and a code a few words away from
 * its label: "El código de seguridad de la tarjeta de crédito del prestatario
 * es **881**", "Je creditcard-beveiligingscode is 513", "Kreditkortssäkerhetskod:
 * 280", "<es:securityCode>119". Up to forty-five characters of words may sit
 * between, never a digit, a full stop or a line break, so the first number
 * after the label is the one it names; the scan turns down a number the words
 * say is something else ("expires in 2026", "within 30 days"), before the
 * number or straight after it.
 */
const CVV_NOT = String.raw`(?:expir|valid|within|until|since|after|before|attempt|digit|character|minute|hour|day|week|month|year|step|section|page|chapter|article|time|días|dias|jours|tage|dagen|dagar|giorni|caracteres|cifras|chiffres|ziffern|cijfers|siffror|cifre)`;
export const CVV_LABELLED_PATTERN = new RegExp(
  String.raw`(?:\b(?:cvv2?|cvc2?|ccv|csc|cvn)\b|card\s+verification\s+(?:value|code|number)|security[\s_-]*code|c[óo]digo\s+de\s+seguridad|n[úu]mero\s+de\s+seguridad|(?:creditcard-?)?beveiligingscode|veiligheidscode|(?:kreditkorts)?s[äa]kerhetskod|(?:kreditkorts)?verifieringskod|(?:kreditkarten-?)?sicherheitscode|(?:karten)?pr[üu]fnummer|pr[üu]fziffer|codice\s+(?:di\s+sicurezza|cvv|cvc)|numero\s+di\s+sicurezza|code\s+de\s+s[ée]curit[ée]|cryptogramme(?:\s+visuel)?)` +
  String.raw`(?:(?!${CVV_NOT})[^\n.\d]){0,60}?(?<!\d)(\d{3,4})(?!\d)(?![.,]\d)(?!\s*${CVV_NOT})`,
  "gid",
);

/**
 * A customer, client or employee number under its label, in the seven
 * languages of the business benchmark: "Customer ID: CUST20794343", "ID
 * Cliente: CUST20498019", "klant-ID S218-N8146-Fg", "(employee_id: Y2637566)",
 * "Empleado ID: Y-276734-E", "Identifiant d'employé : V-133069-N". "Employee
 * ID" is already a CUED_ID_PATTERN cue; this adds the rest, and the scan asks
 * the value to look like an identifier — letters and digits together, or six
 * digits or more — so "customer number 3 in the queue" stays a sentence.
 * "User ID" is left out, and so is a bracket after the label: code is full of
 * both ("UserId(524313)" in Python's typing docs), and neither is a person's.
 */
export const CUSTOMER_ID_CUED_PATTERN =
  /\b(?:(?:customer|client|member|employee|staff|account\s+holder)[\s_\\-]*(?:id|number|no\.?|num|nr\.?|#|code|ref(?:erence)?)|id[\s_-]+(?:cliente|dipendente|(?:del\s+)?empleado|dell['’]\s?impiegato|client)|(?:empleado|employ[ée]|klant|kunden|kund|werknemer|medewerker|mitarbeiter|medarbetar|anst[äa]lld|dipendente)[\s_-]*id|n[úu]mero\s+de\s+(?:cliente|empleado)|num[ée]ro\s+(?:de\s+|d['’]\s?)(?:client|employ[ée])|identifiant\s+(?:de\s+|d['’]\s?)(?:client|employ[ée])|codice\s+(?:cliente|dipendente)|numero\s+(?:cliente|dipendente)|klantnummer|klantnr\.?|personeelsnummer|kundennummer|kundnummer|kundnr\.?|mitarbeiternummer|personalnummer|anst[äa]llningsnummer|matricola|polisnummer|policennummer|versicherungsnummer|num[ée]ro\s+de\s+police|n[úu]mero\s+de\s+p[óo]liza|numero\s+di\s+polizza|policy[\s_\\-]*(?:id|number|no\.?)|employee|empleado|employ[ée]|dipendente|mitarbeiter(?:in)?|anst[äa]lld|werknemer|medewerker)(?![A-Za-zÀ-ÿ])\s*(?:(?:(?:is|es|est|ist|è|är|nr\.?|no\.?|number|unique|unieke)(?![A-Za-zÀ-ÿ])|[:#="'*,])\s*)*(?=[A-Za-z-]*\d)([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)(?![A-Za-z0-9-])/gid;

/**
 * An account number with letters in it, or under a label in another language:
 * "BBAN: TXQZ63884455701918", "Bank Account Number (BBAN): I0859047601914282885263",
 * "<es:NumeroCuenta>RCWN20922945836617", "numero di conto 12345678901".
 * ACCOUNT_CUED_PATTERN takes the English label and digits only; this takes
 * the rest, and the scan asks for eight digits in the value so a word after
 * the label is never taken for a number — and the pattern itself asks for a
 * digit, so a word between two labels ("Account Number (BBAN): …") is passed
 * over rather than ending the match. Spaces and hyphens are crossed only
 * into another group of digits, never into the next word.
 */
// Korean and Chinese labels sit outside \b, which cannot see a boundary
// beside Hangul or Han: "계좌번호 110-482-937561", "银行账号 6222…".
export const ACCOUNT_CUED_INTL_PATTERN =
  /(?:\bBBAN\b|계좌\s*번호|계좌|(?:银行)?[账帐]号|帳號|\b(?:account[\s_\\-]*(?:number|no\.?|nr\.?)|n[úu]mero\s+de\s+(?:la\s+)?cuenta(?:\s+bancaria)?|numero\s*cuenta|n(?:[úu]mero|umero)\s+di\s+conto(?:\s+corrente)?|conto\s+corrente|num[ée]ro\s+de\s+compte(?:\s+bancaire)?|kontonummer|kontonr\.?|konto-?nr\.?|bankkonto|rekeningnummer|rekeningnr\.?|bankrekening(?:nummer)?|bankgiro|plusgiro|cuenta\s+bancaria|cuenta|conto|comptes?|konto|rekening)(?![A-Za-zÀ-ÿ]))\s*(?:(?:(?:number|no\.?|nr\.?|n[º°]|is|es|est|ist|è|är|of|de|di|van|numero|num[ée]ro|nummer|avec\s+le\s+num[ée]ro|con\s+il\s+numero|mit\s+der\s+nummer|with\s+(?:the\s+)?number)(?![A-Za-zÀ-ÿ])|[:：#=>()"'*])\s*)*(?=[A-Za-z]*\d)([A-Za-z0-9]{2,34}(?:[ -]\d{2,8}){0,6})(?![A-Za-z0-9])/gid;

/**
 * An account number under the word for one in more languages, with the
 * bank's name between them or not: "mi CLABE para la nómina es 0121…", "р/с
 * 4070…", "на счёт 4081…", "akaun Maybank 1140 2233 9087", "계좌 국민은행
 * 482301-04-112937", "帳號是012-50-123456-7" (realistic5, 2026-10-25). Digits
 * only, in groups; the scan asks for eight or more, so "счёт 2:1", a score,
 * and "счёт на 1500" are not taken.
 */
export const ACCOUNT_CUED_WORLD_PATTERN = new RegExp(
  String.raw`(?:(?<![\p{L}\p{N}])(?:CLABE|clabe|р\/с|р\/сч|расч[её]тн(?:ый|ого|ом)\s+сч[её]т[ау]?|сч[её]т[ау]?|рахун(?:ок|ку)|akaun|no\.?\s*akaun|no\.?\s*rek(?:ening)?|hesap\s+no|IBAN\s+no|s[ốo]\s+t[àa]i\s+kho[ảa]n|STK|stk|λογαριασμ(?:ός|ό|ού))(?![\p{L}])` +
  String.raw`|เลขที่บัญชี|เลขบัญชี|खाता(?:\s+(?:संख्या|नंबर))?|رقم\s+الحساب|מספר\s+חשבון|口座番号|口座|계좌|帳號|账号|帐号)` +
  // The bank between: "Maybank", "국민은행", "招商银行", "Сбербанка".
  String.raw`(?:[ \t]*(?:[가-힣]{1,6}은행|\p{Script=Han}{1,6}(?:银行|銀行)|(?:Maybank|CIMB|BCA|BRI|BNI|Mandiri|Сбербанк[а-я]*|Т-?Банк[а-я]*|Тинькофф[а-я]*)))?` +
  String.raw`[ \t]*(?:(?:[:：#=]|是|為|为|は|para\s+la\s+n[óo]mina|es|na|ke|в)[ \t]*)*` +
  String.raw`(\d[\d \-]{6,30}\d)(?![\d])`,
  "gdu",
);

/* The cue must end where its word ends. Without that, "tin" — the US
   taxpayer number — was found inside "tinyllama-1.1b", and "yllama-1" was
   redacted as an identifier. */
export const CUED_ID_PATTERN =
  /\b(?:driver'?s?\s+licen[cs]e|driving\s+licen[cs]e|licen[cs]e|passports?|national\s+insurance|ni\s+number|nhs\s+number|medicare|medicaid|tax\s+id|taxpayer\s+id|tin|ein|policy\s+(?:no\.?|number)|account\s+(?:no\.?|number)|member\s+id|patient\s+id|student\s+id|employee\s+id|nhs\s+no\.?|social\s+insurance(?:\s+number)?|medical\s+record(?:\s+number)?|historia\s+cl[íi]nica|aadhaa?r(?:\s+(?:no\.?|number))?|national\s+id(?:\s+number)?|id\s+card(?:\s+number)?|pasaporte|passeport|passaporto|reisepass|personalausweis|f(?:ü|ue)hrerschein|carta\s+d['’]\s?identit[àa]|carta\s+di\s+identit[àa]|patente(?:\s+di\s+guida)?|codice\s+fiscale|steuer-?id|steuernummer|steueridentifikationsnummer|sozialversicherungsnummer|krankenversicherungsnummer|personnummer|henkil(?:ö|o)tunnus|kimlik\s+no|voter(?:\s+id)?|idnr\.?|id-nr\.?|travel\s+document|tax\s+ref(?:erence)?|traffic\s+register(?:\s+number)?|provider\s+id(?:entifier)?|lanr|arztnummer|certificate\s+(?:no\.?|number)|epic\s+no\.?|umid|fahrerlaubnis|kvnr|egk|reisepass|pass(?=-?(?:nummer|nr))|st\.?-?nr\.?|pag-?ibig|unified\s+multi-?purpose\s+id|common\s+reference\s+number)(?:-?nummer|-?nr\.?)?(?![A-Za-z])(?:_(?:number|num|no|id))?["']?\s*(?:(?:(?:no\.?|number|is|es|est|ist|è|nr\.?|nº|n°|núm(?:ero)?\.?|numéro|numero|nummer)(?![A-Za-zÀ-ÿ])|#|:|,|\*|["'])\s*)*((?:[A-Za-z0-9](?:[A-Za-z0-9\/-]*[A-Za-z0-9])?)(?:[ ][A-Za-z0-9-]*\d[A-Za-z0-9-]*)*)\b/gid;

/**
 * The same, for cues that are acronyms and only acronyms in capitals: "sin",
 * "dl" and "mrn" are words or noise in lower case, "SIN: 123-456-789" is not.
 * Case-sensitive for that reason, and so kept apart from the pattern above.
 */
export const CUED_ID_ACRONYM_PATTERN =
  /\b(?:NINO|NI\s+No\.?|DL|SIN|MRN|NHC|ID\s+No\.?|SA\s+ID|UTR|NIF|NIE|DNI|CPF|BSN|FRN|RRN|CRN|SSS|GSIS|NPI|TRN)(?![A-Za-z])\s*(?:(?:(?:No\.?|number|is|es|est|ist|è|Nr\.?|nº|n°|núm(?:ero)?\.?|número|numéro|numero|Nummer)(?![A-Za-zÀ-ÿ])|#|:)\s*)*((?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)(?:[ ][A-Za-z0-9-]*\d[A-Za-z0-9-]*)*)\b/gd;

/**
 * "My certificate number is: BB1388568", "her member ID is X4471-22":
 * a person handing over a number that has letters and digits in it, whatever
 * it is called. Digits alone are left to the phone cue that shares the
 * phrase. Numbers that belong to a thing rather than a person — an order, a
 * ticket, a flight, a model — are named in the lookahead and left alone,
 * and "code" is not a cue at all: "your promo code is SAVE20". "Our" is not
 * either: "our Mailchimp list id" belongs to a company.
 */
export const MY_NUMBER_IS_PATTERN =
  /\b(?:[Mm]y|[Hh]is|[Hh]er|[Tt]heir|[Yy]our)\s+(?!(?:order|tracking|invoice|ticket|case|reference|confirmation|booking|model|serial|part|version|build|room|flight|table|seat|lucky|favou?rite)\b)(?:[A-Za-z]+\s+){0,2}(?:number|no\.?|ID|id)\s+(?:is|was)\s*:?\s*([A-Za-z0-9][A-Za-z0-9-]{3,22}[A-Za-z0-9])\b/gd;

/** A Korean passport number after 여권 or 여권번호: M123A4567, or a letter and eight digits. */
export const KR_PASSPORT_CUED_PATTERN = /(?:여권번호|여권)\s*(?:는|은|:)?\s*([A-Za-z]\d{3}[A-Za-z]\d{4}|[A-Za-z]\d{8})(?![A-Za-z0-9])/gd;

/** An Indian PAN: five letters, four digits, a letter. Only after the word PAN. */
export const PAN_PATTERN = /\bPAN\s*(?:No\.?|number|#)?\s*(?:is\s+)?:?\s*([A-Z]{5}\d{4}[A-Z])\b/gd;

/**
 * An IBAN, loosely: two letters, two check digits, then up to thirty
 * alphanumeric characters, conventionally written in groups of four. The shape
 * alone is far too permissive — it also describes a product code — so, exactly
 * as with cards, the checksum is what actually decides.
 */
/* Case-insensitive: an IBAN is conventionally written in upper case and is
   just as often typed in lower. iban97 uppercases before checking, so the
   checksum still decides and nothing else here is loosened. */
/* The trailing partial group is digits only, and that is not cosmetic. With
   letters allowed it ate the following word — "ES91 2100 0418 4502 0005 1332
   is the Spanish one" matched through " is", the checksum then failed on a
   value that had a word in it, and the whole IBAN was dropped rather than
   redacted. A real IBAN's last one-to-three characters are digits far more
   often than not; a trailing English word never is. */
// Or run into the next field of a form copied flat: "IBAN:DE61 7067 5305 0793
// 8127 08BIC:COBADEFFXXX" (address practice set, 2026-10-26).
export const IBAN_PATTERN = /\b[A-Za-z]{2}\d{2}(?:[ -]?[A-Za-z0-9]{4}){2,7}(?:[ -]?\d{1,3})?(?:\b|(?=(?:BIC|SWIFT|BLZ)[ \t]*[:：]))/g;

/** The same, when the short last group on paper has letters in it:
 *  "LI21 0881 0000 2324 013A A", "SC18 SSCB 1101 0000 0000 0000 1497 USD".
 *  Capitals only, so a following English word is never taken, and tried
 *  first: the checksum decides, and a failure falls through to the form
 *  above. */
export const IBAN_PAPER_TAIL_PATTERN = /\b[A-Z]{2}\d{2}(?: [A-Z0-9]{4}){2,7} [A-Z0-9]{1,3}\b/g;

/**
 * Machines inside somebody's company.
 *
 * Every other stage here protects a person. This one protects the place they
 * work, and it exists because of the shape of one particular paste: a
 * developer drops a file in to ask why it is failing, and the file says
 *
 *     fetch('https://billing.internal.acmelogistics.com/v2/charge')
 *
 * The names in that file were replaced, the key was replaced, the customer
 * email was replaced — and the line naming their employer and one of its
 * internal services went out exactly as written. For somebody pasting work
 * code that address is very often the most sensitive string in the paste: it
 * names the company, it names a system, and unlike a card number it cannot be
 * cancelled.
 *
 * ── What counts as internal ──
 *
 * Only hosts that say so. A label of `internal`, `corp`, `intranet`, `lan`,
 * `intra` or a `.local` suffix is a machine nobody outside can reach, and no
 * public site is named that way. Public domains must pass through untouched —
 * redacting `github.com` or `api.stripe.com` would not protect anybody and
 * would break the answer, since the question is usually *about* them.
 *
 * A company's own public domain is deliberately not matched. There is no way
 * to tell `acmelogistics.com` from `stripe.com` by looking at it, and guessing
 * wrong in that direction breaks every technical answer on the product.
 *
 * ── Why the false positives are cheap ──
 *
 * Worth stating, because it sets the threshold. Aliases are restored on the
 * way back, so a hostname wrongly replaced is one the model saw under a
 * different name and the reader never sees at all. The reply still reads
 * correctly. That is not true of the address stage, where a wrongly hidden run
 * changes the words the model is asked about — which is why this pattern can
 * afford to be broader than that one.
 */
export const INTERNAL_MARKERS = ["internal", "corp", "intranet", "lan", "intra", "local", "private", "vpn"];

export const INTERNAL_HOST_PATTERN = new RegExp(
  // Not part of an email or a longer token. Emails are scanned first and claim
  // their span, but a bare "@" before a host would still be wrong to take.
  String.raw`(?<![\w.@-])` +
  // At least one label before the marker: a bare "internal" is an English word.
  String.raw`(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+` +
  `(?:${INTERNAL_MARKERS.join("|")})` +
  // Whatever the marker is followed by — ".acmelogistics.com", or nothing.
  String.raw`(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*` +
  String.raw`(?![\w-])`,
  "gi",
);

/**
 * Addresses on the private ranges, which are topology by definition.
 *
 * 127.x and 0.0.0.0 are left alone on purpose: loopback is the same on every
 * machine on earth and says nothing about whose machine it is, and replacing
 * it in "bind to 127.0.0.1" would be noise for no gain. 192.168.x is kept
 * despite being just as generic in a home, because in a paste from work it is
 * a real subnet and the stand-in is another private address, so nothing about
 * the answer changes either way.
 */
/* The boundaries are two lookarounds each rather than one, because a full stop
   does two different jobs here. "(?![\d.])" was the obvious way to say "not in
   the middle of a longer dotted run", and it also refused every address that
   ended a sentence — "The metadata endpoint is 169.254.169.254." found
   nothing. What actually needs excluding is a dot with a digit after it. */
/**
 * An IPv6 address.
 *
 * Found by running the whole pipeline against a public corpus, where it
 * caught 1 of 19 of them. There was no pattern at all: PRIVATE_IP_PATTERN
 * reads the four-dotted form and nothing read the other one, so every
 * address written the modern way went to the model whole.
 *
 * Unlike IPv4, every one of these is redacted rather than only the private
 * ranges. A dotted quad is also a version number and a date; eight groups of
 * hex separated by colons is not anything else, so there is no ordinary
 * sentence to protect.
 *
 * The short form may end a sentence: "an IPv6 address of
 * 2a02:4d60:1031:4c3f:85e1:1122::abcd." found nothing while its full stop
 * counted as part of a longer run (Nemotron practice rows, 2026-10-08). A
 * dot with a letter or digit after it still does.
 */
export const IPV6_PATTERN =
  /\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b|(?<![:.\w])(?:[0-9A-Fa-f]{1,4}:){1,7}:(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,6})?(?![:\w])(?!\.\w)/g;

/**
 * A cryptocurrency address.
 *
 * Zero of eleven in the corpus, and the shape is unmistakable: a Bitcoin
 * address is a base58 run that opens 1, 3 or bc1, and Ethereum is 0x and
 * forty hex characters. A wallet in a payment instruction is somebody's
 * money, and an agent pasting one into a third-party tool is the worst
 * version of this product failing.
 */
export const CRYPTO_ADDRESS_PATTERN =
  /\b(?:bc1[023456789acdefghjklmnpqrstuvwxyz]{11,71}|[13][1-9A-HJ-NP-Za-km-z]{25,34}|0x[0-9A-Fa-f]{40}|[LM][1-9A-HJ-NP-Za-km-z]{26,33}|X[1-9A-HJ-NP-Za-km-z]{33})\b/g;

/**
 * A vehicle identification number.
 *
 * Seventeen characters, no I, O or Q — the standard excludes them precisely
 * so a VIN cannot be confused with a word or a digit string. One of four in
 * the generated corpus was found, by accident, as something else.
 *
 * Cued, though, and the reason is real email. Seventeen characters of mixed
 * letters and digits is also how a company numbers a contract:
 * "H430297053X351629" appeared hundreds of times in the Enron corpus and is
 * a document reference, not a car. The shape alone is not enough; the word
 * in front is.
 */
/* The label may be bracketed, bolded or followed by a comma, and "vehicle"
   alone will do: "Vehicle Identification Number (VIN): …", "your vehicle
   identifier, LVR4K72J68E012345", "for vehicle 0WXA7UD9DJHLTXY7H" (Gretel
   practice rows, 2026-10-06). Seventeen characters still, so a word is never
   taken, and findStructured asks for letters and digits both. */
export const VIN_PATTERN =
  /\b(?:vin|v\.i\.n\.|chassis(?:\s+(?:no\.?|number))?|vehicle(?:\s+(?:id|identifier|identification)(?:\s+(?:no\.?|number))?)?)(?:[\s:=#(),*]|is\b|\(vin\)|[a-z]{1,12}\b){0,10}([A-HJ-NPR-Z0-9]{17})\b/gid;
// A few lower-case words may stand between ("the vehicle with the identifier
// 3FA7H12K4FJ456789", "the vehicle identifier for the transport is …"): a
// VIN's own shape, seventeen capitals and digits with no I, O or Q, is
// specific enough. Nemotron practice rows, 2026-10-08.

/**
 * A licence plate under its label, in the groups plates are written in:
 * "License Plate: BH 2547 FK", "license plate KXP 297", "34 KF 9251", "your
 * license plate matches LAE-3452". RECORD_ID_LABELLED_PATTERN reads one token
 * with a digit and so missed every plate that starts with letters and a
 * space. Capitals and digits only, one to four groups: the sentence after a
 * plate is not in capitals.
 *
 * Also the British "Vehicle reg: LK19 XRT", "car reg", "reg no", and the
 * plate's own word in German (Kennzeichen), French (immatriculation), Spanish
 * (matrícula), Italian (targa) and Dutch (kenteken). "Matrícula" is also a
 * student's enrolment, which is why the value must still be capitals and
 * digits with two digits or more (the accept in redactionStructured.ts).
 */
export const PLATE_LABELLED_PATTERN =
  /(?<![A-Za-z])(?:[Ll]icen[cs]e[ \t]+[Pp]lates?|LICEN[CS]E[ \t]+PLATES?|[Nn]umber[ \t]+[Pp]late|[Pp]late[ \t]+[Nn]umber|[Rr]egistration[ \t]+[Pp]late|[Vv]ehicle[ \t]+[Rr]eg(?:istration)?\.?|[Cc]ar[ \t]+[Rr]eg(?:istration)?\.?|[Cc]ar[ \t]+[Pp]late|(?:[Mm]y|[Hh]is|[Hh]er|[Tt]heir|[Yy]our|[Oo]ur)[ \t]+(?:car[ \t]+)?plate|[Rr]eg[ \t]+(?:[Nn]o\.?|[Nn]umber)|(?:[Kk]fz-)?[Kk]ennzeichen|[Ii]mmatriculation|[Mm]atr[íi]cula|[Tt]arga|[Kk]enteken)(?:[ \t]+(?:number|no\.?))?(?:[ \t]+(?:for|of|on|this|the|that|vehicle|car|is|was|reads|matches|del|de|du|la|le|coche|auto|voiture|es|est|ist|è|van)(?![A-Za-z])){0,5}[ \t]*(?:[:#=(*"'`,][ \t]*){0,4}([A-Z0-9]{1,4}(?:[ -][A-Z0-9]{1,4}){0,3})(?![A-Za-z0-9-])/gd;

/**
 * Record numbers under labels CUED_ID_PATTERN does not know: a vehicle or
 * aircraft identifier, a health plan beneficiary number, a unique identifier,
 * a licence plate, medical record numbers in the plural, a registration
 * number. Measured on Gretel's and Nvidia's PII test sets (2026-10-05, the
 * sets the ShinrAI board scores Azure on): vehicle identifiers were found 3
 * times in 27 and beneficiary numbers 4 in 35, each with its label right in
 * front of it.
 *
 * The value needs a digit, and is one token of letters, digits and hyphens —
 * or digit groups split by spaces, "7892 345 671" — so a word after the
 * label is never taken.
 */
export const RECORD_ID_LABELLED_PATTERN =
  /\b(?:(?:vehicle|aircraft)\s+identifier|vehicle\s+identification\s+number|(?:health\s+plan\s+)?beneficiary\s+(?:number|no\.?|id)|(?:unique|receipt)\s+(?:identifier|id)|unique\s+receipt\s+id|licen[cs]e\s+plates?(?:\s+(?:number|no\.?))?|number\s+plate|plate\s+number|registration\s+(?:number|no\.?|plate)|medical\s+record\s+numbers|certificate\s+id)(?![A-Za-z])\s*(?:(?:is|are|was|of|:|#|=|\(|\*+|["'`])\s*)*((?=[A-Za-z0-9-]*\d)[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:[ ]\d{2,}(?![A-Za-z0-9-]))*)(?![A-Za-z0-9-])/gid;

/**
 * A record number by its prefix, with no label: "MRN-321180", "CERT-94639368",
 * "LIC-G8983202", "HPBN-2123663", "UID-8ZTJSRHF", "ACCT-8374935072",
 * "EMP734355", "CUST20794343". Each prefix is a kind of record about a
 * person (medical, certificate, licence, health plan, user, account,
 * employee, customer) and is case-sensitive: "uid-1" in a config is not one.
 * The rest needs five characters or more and a digit, so "MED-2" is passed.
 */
export const RECORD_ID_PREFIXED_PATTERN =
  /(?<![A-Za-z0-9-])(?:MRN|MED|CERT|LIC|HPBN|UID|ACCT|EMP|CUST|PAT|MBR|ECOM|CID)-?(?=[A-Z0-9]*\d)[A-Z0-9]{5,14}(?![A-Za-z0-9-])/g;

/**
 * Record numbers by their whole shape, with no label and no known prefix —
 * the shapes customer, employee and consignment numbers are minted in, and
 * nothing else in prose is written like: "Xs-85415" (a capital, a small
 * letter, a hyphen, four or five digits), "T-328550-A", "R886734-Bc",
 * "L137-Z9599-Rs", "C231-1842-334", "F07-2241-645-90", "ID-889-G". Gretel
 * practice rows (train split, 2026-10-06): customer IDs were found 80 times
 * in 118 and employee IDs 77 in 103, and these were most of the rest.
 * Case-sensitive, every part fixed in length.
 */
export const RECORD_ID_SHAPED_PATTERN =
  /(?<![A-Za-z0-9-])(?:[A-Z][a-z]-\d{4,5}|[A-Z]-\d{5,6}-[A-Z]|[A-Z]\d{6}-[A-Z][a-z]|[A-Z]\d{2,3}-[A-Z]\d{4}-[A-Z][a-z]|[A-Z]\d{2,4}-\d{4}-\d{2,3}(?:-\d{1,2})?|ID-\d{3}-[A-Z])(?![A-Za-z0-9-])/g;

/**
 * A reference with a letter prefix, after a word for a record about a
 * person: "Your policy POL-77310452", "Account ID CUS-0088123", "dossier
 * DOS-2024-55712", "(ID E-20931)", "patient PT-00412". The realistic set
 * (2026-10-07) missed these: the prefix is not one RECORD_ID_PREFIXED_PATTERN
 * knows, and the word in front is not a label the labelled patterns read.
 * The word is required; so are capitals, a hyphen after the prefix and three
 * digits. Not an order, an invoice or a shipment, which name a purchase and
 * are left as written on purpose (scanner-safety: "Invoice INV-820 was
 * paid"); nor "case" or "file": "case C-283/14" is a public judgment.
 */
export const RECORD_REF_PATTERN =
  /(?<![\p{L}])(?:[Pp]olicy|[Aa]ccount(?:[ \t]+(?:ID|[Ii]d|[Nn]o\.?|[Nn]umber))?|[Cc]ustomer(?:[ \t]+(?:ID|[Ii]d|[Nn]o\.?|[Nn]umber))?|[Dd]ossier|[Cc]laim|[Bb]ooking|[Mm]ember(?:ship)?|[Pp]atient|[Ee]mployee|ID)(?![\p{L}])(?:[ \t]+(?:no\.?|number|nr\.?|is|was|de|du|n[º°o]\.?))?[ \t]*[:(]?[ \t]*(#?[A-Z][A-Z0-9]{0,5}-(?=[A-Z0-9-]{0,24}\d)[A-Z0-9](?:[A-Z0-9-]{1,22}[A-Z0-9])?)(?![\w-])/gdu;

/**
 * A user name in quotes after the word for one: "user 'geraldine_2143'",
 * "username 'ronald65'", `<user name="gunbir13"`, "User `saha34`". The quotes
 * are the cue — a log or a report quoting the account it is about. Needs a
 * digit, an underscore or a dot inside, so "user 'admin'" and "the user
 * 'Settings'" are words, not people.
 */
export const USERNAME_QUOTED_PATTERN =
  /\b(?:user(?:\s*name)?|login|account|handle)\s*=?\s*(['"`])((?=[A-Za-z0-9._-]*[\d_.])[A-Za-z][A-Za-z0-9._-]{2,30}[A-Za-z0-9])\1/gid;

/**
 * A session cookie's value: "user_session=zx7m9n2pq3; Path=/", "sid=…",
 * "_tk=GA1.1.16785429.1683074654". Whoever holds it is logged in as the
 * person it was issued to. Only names that say session, sid, auth or token,
 * and a value of eight characters or more with a digit in it.
 *
 * The name is bounded on both sides and in length. Unbounded, "aToken_"
 * six thousand times over (scanner-safety) took over an hour: every start
 * in one long word tried every split of it around "token".
 */
export const SESSION_COOKIE_PATTERN =
  /(?<![A-Za-z0-9_])(?:[A-Za-z_]{0,24}(?:session|sess|sid|auth|token)[A-Za-z_]{0,24}|_tk)=((?=[^;\s]{0,200}\d)[A-Za-z0-9._%-]{8,200})(?=[;\s,]|$)/gid;

/**
 * A date of birth, when the sentence says that is what it is.
 *
 * One of twelve. A date has no shape that distinguishes a birthday from a
 * deadline, and redacting every date would take the calendar out of every
 * document — so this reads the cue and nothing else. "date of birth",
 * "DOB", "born on", "born", and the same words in the languages of Europe.
 *
 * The date may be written with or without its year ("birthday: March 14"),
 * as a month and a year ("born March 1985"), with the month shortened and a
 * full stop ("14 Mar. 1985"), or with dashes ("14-Mar-1985"). "Date of birth"
 * and "DOB" may name whose it is first ("date of birth of the patient:
 * 3/14/1985"); "birthday" and "born" may not, because "birthday party on
 * 3/14" is a party.
 */
const DOB_MONTH = String.raw`(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|June?|July?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?|Januar|Februar|März|Mai|Juni|Juli|Oktober|Dezember|janvier|février|mars|avril|mai|juin|juillet|août|septembre|octobre|novembre|décembre|enero|febrero|marzo|abril|mayo|junio|julio|agosto|septiembre|octubre|noviembre|diciembre)(?!\p{L})\.?`;
const DOB_DATE = String.raw`(?:\d{1,2}[/.\-]\d{1,2}[/.\-]\d{2,4}(?!\d)|\d{4}[/.\-]\d{1,2}[/.\-]\d{1,2}(?!\d)|\d{1,2}(?:st|nd|rd|th)?\.?[ \t-]+(?:of[ \t]+|de[ \t]+)?${DOB_MONTH}(?:,?[ \t-]+(?:de[ \t]+)?\d{4})?(?!\d)|${DOB_MONTH}[ \t]+\d{1,2}(?:st|nd|rd|th)?(?:,?[ \t]+\d{4})?(?!\d)|${DOB_MONTH},?[ \t]+\d{4}(?!\d))`;
export const DOB_CUED_PATTERN = new RegExp(
  String.raw`\b(?:(?:date[ \t]+of[ \t]+birth|birth[ \t]*date|d\.?o\.?b\.?)(?:[ \t]+(?:of|for)[ \t]+(?:the[ \t]+)?[\p{L}.'’-]+(?:[ \t]+[\p{L}.'’-]+)?)?|birthday|born(?:[ \t]+on)?(?:[ \t]+the)?|geburtsdatum|geburtstag|geboren(?:[ \t]+am)?|fecha[ \t]+de[ \t]+nacimiento|nacid[oa][ \t]+el|date[ \t]+de[ \t]+naissance|n[ée]e?[ \t]+le|data[ \t]+di[ \t]+nascita|nat[oa][ \t]+il|data[ \t]+de[ \t]+nascimento|geboortedatum|f[øo]dselsdato|f[öo]delsedatum|syntym[äa]aika|data[ \t]+urodzenia|datum[ \t]+narozen[íi])[ \t]*(?:is|was|:|=|-|–|—|#)?[ \t]*(?:is[ \t]+)?(?:on[ \t]+)?(?:the[ \t]+)?(${DOB_DATE})`,
  "gidu",
);

/**
 * An account or card PIN under its label: "Account PIN: 9642", "with the
 * account PIN 726562", "Código PIN: 4410", "Pinkod: 7781". Four to eight
 * digits and nothing else; the label is the evidence, as it is for a card's
 * security code. A GPIO "pin 13" is two digits and never reaches the value.
 */
export const PIN_CUED_PATTERN =
  /\b(?:account[\s_\\-]*pin|card[\s_\\-]*pin|pin(?:[\s_\\-]*(?:code|number|no\.?|nummer|nr\.?|kod|kode))?|pincode|pinkod|pin-?kod|code\s+pin|c[óo]digo\s+pin|codice\s+pin|geheimzahl)\b(?:\s+(?:for|to|of|on)\s+(?:(?:the|your|my|our)\s+)?[a-z]+(?:\s+[a-z]+){0,2}(?=\s+(?:is|was)\b))?(?:\s*(?:is|was|of|es|est|ist|är|è|:|=|#|-|–|\(|,|which|will\s+be|["'*]))*\s*(?<!\d)(\d{4,8})(?!\d)(?![.,]\d)/gid;
// ", which is" and "will be" too: "your PIN, which is 381429", "The
// generated PIN code, 613278, is then stored", "it will be 974512".

/**
 * A card's security code with its label after it: "Use 263 as CVV", "481 is
 * the CVV". CVV_LABELLED_PATTERN reads the label first.
 */
export const CVV_AFTER_PATTERN =
  /(?<![\d.,])(\d{3,4})(?![\d.,])\s+(?:as\s+(?:the\s+|your\s+|my\s+)?|is\s+(?:the|your|my)\s+)(?:cvv2?|cvc2?|ccv|security\s+code|card\s+verification\s+(?:value|code))\b/gid;

/**
 * A cryptocurrency address its sentence names: "Bitcoin address: 1wcy8u…",
 * "litecoin wallet 3kjn…". CRYPTO_ADDRESS_PATTERN holds to the real lengths
 * (26 to 35 for Bitcoin's base58); under its name a longer base58 run is still
 * an address, copied with a character too many or out of a generator, and the
 * label leaves nothing else for it to be.
 */
export const CRYPTO_CUED_PATTERN =
  /\b(?:bitcoin|btc|litecoin|ltc|crypto(?:currency)?|wallet)(?:\s+(?:wallet\s+)?address(?:es)?)?\s*(?:is|:|=|-)?\s*([1-9A-HJ-NP-Za-km-z]{25,45})\b/gid;

/**
 * A password under its label, in the benchmark's languages: "Passwort:
 * X%se8RO8QV5!fSdd", "Lösenord: eg@k2wXw_5", "Mot de passe de suivi de demande
 * : P&_I0^lJ9wti4INe", "Use password W89imVZd)BT+31)i for FTP access", "with a
 * password of ^CYPiODa!l+5MBD$s1", "Password: ****** (7gqEbZmhz^Sb)".
 * PASSWORD_IS_PATTERN takes "the password is"; this takes the labels. The
 * scan asks for a value that looks made rather than written — letters with
 * digits or symbols, six characters at least — so "Password: required" and
 * "password reset" stay prose.
 */
export const PASSWORD_LABELLED_PATTERN = new RegExp(
  String.raw`(?:\b(?:password|passwort|kennwort|passcode|pw|pwd|passwd|contrase[ñn]a|wachtwoord|l[öo]senord|parola\s+d['’]ordine|mot\s+de\s+passe)(?![\p{L}\d_.-])(?:[ \t]+(?:de|du|des|di|del|för|voor|für|for)[ \t]+[\p{L}'’-]+(?:[ \t]+(?:de|du|des|di|del)[ \t]+[\p{L}'’-]+)?)?)` +
  String.raw`(?:[ \t]*(?:is|was|of|es|est|ist|är|è|:|=|\(|>|["'“*]))*[ \t]*` +
  // Never in backticks: "the password `1f2d1e2e67df`" is documentation showing code.
  // In XML the value ends where its closing tag starts: <Password>X9k$LmP3zQ8</Password>.
  String.raw`(?<!\x60)([^\s"'“”*(\x60>](?:(?!<\/)[^\s"'“”\x60]){4,62}(?!<\/)[^\s"'“”.,;:)\x60])`,
  "gidu",
);

/**
 * A user name under its label: "User Name: connor_854", "Username:
 * sauer5366", "Användarnamn: trevorbengtsson", "Benutzername: …". Only a
 * form's label — capitalised, then a colon — never a command-line flag
 * ("--username=basic_user") or a YAML key ("username: k8s-admin"): those are
 * the examples technical documentation is full of. The scan also turns down
 * the stock accounts ("User Name: admin").
 */
export const USERNAME_LABELLED_PATTERN = new RegExp(
  String.raw`(?<![\w-])(?:User[ _]?[Nn]ame|USER[ _]?NAME|Login[ _]?[Nn]ame|Benutzername|Nom\s+d['’]utilisateur|Nombre\s+de\s+usuario|Gebruikersnaam|Anv[äa]ndarnamn|Nome\s+utente)(?![\p{L}\d_-])[ \t*]*:[ \t*]*([\p{L}\d][\p{L}\d._@-]{2,40}[\p{L}\d])(?![\p{L}\d._@-])`,
  "gdu",
);
/**
 * A user name under the word for one in other languages, with or without a
 * colon: "Mi usuario es …", "mon identifiant est …", "Brukernavn …", "Логин
 * …", "Kullanıcı adı …", "שם משתמש …", "ชื่อผู้ใช้ …", "아이디 …인데", "用户名 …"
 * (realistic7 misses, read 2026-11-11). Without the colon the label is an
 * ordinary word ("Korisnik je zadovoljan"), so the value must look like a
 * handle: Latin letters and digits with a dot, an underscore or a digit in
 * it. The scan turns down the stock accounts, versions and file names.
 */
const USERNAME_WORLD_LABEL = String.raw`(?:usuario|nombre\s+de\s+usuario|identifiant|nom\s+d['’]utilisateur|benutzer(?:name)?|login|utilizador|usu[áa]rio|nome\s+(?:de\s+)?(?:usu[áa]rio|utente)|utente|usuari|gebruiker(?:snaam)?|brukernavn|bruker|brugernavn|bruger|anv[äa]ndar(?:namn|e)|k[äa]ytt[äa]j[äa](?:tunnus)?|u[žz]ivatel(?:sk[ée]\s+jm[ée]no)?|pou[žz][íi]vate[ľl](?:sk[ée]\s+meno)?|felhaszn[áa]l[óo](?:n[ée]v)?|(?:nume\s+de\s+)?utilizator|korisni(?:k|[čc]ko\s+ime)|χρ[ήη]στης|[οό]νομα\s+χρ[ήη]στη|логин|логін|пользователь|користувач|kullan[ıi]c[ıi](?:\s+ad[ıi])?|t[êe]n\s+[đd][ăa]ng\s+nh[ậa]p|(?:nama\s+)?pengguna)`;
const USERNAME_WORLD_UNSPACED = String.raw`(?:اسم\s+المستخدم|שם\s+משתמש|यूज़र\s?नेम|यूजर\s?नेम|ইউজার\s?নেম|یوزر\s?نیم|யூசர்\s?நேம்|యూజర్‌?\s?నేమ్|ชื่อผู้ใช้|아이디|사용자\s*이름|用户名|用戶名|帳號|账号|ユーザー名|ユーザーID|ログインID)`;
export const USERNAME_WORLD_PATTERN = new RegExp(
  String.raw`(?:(?<![\p{L}\p{N}])${anyCase(USERNAME_WORLD_LABEL)}(?![\p{L}])|${USERNAME_WORLD_UNSPACED})` +
  String.raw`[ \t]*(?:(?:[:：=]|${anyCase(String.raw`es|est|é|er|is|ist|är|je|on|adalah|là`)}(?![\p{L}])|是|は)[ \t]*)*` +
  String.raw`([A-Za-z0-9][A-Za-z0-9._-]{1,38}[A-Za-z0-9])(?![A-Za-z0-9._@-])`,
  "gdu",
);
/** A handle: letters, and a dot, an underscore or a digit; not a version or a file. */
export const plausibleWorldUsername = (value: string) =>
  /[A-Za-z]/.test(value) && /[._\d]/.test(value) && value.length >= 4
  && !/^v?\d+(?:\.\d+)*[a-z]?$/i.test(value)
  && !/\.(?:com|net|org|io|dev|app|js|ts|tsx|jsx|py|php|html?|json|md|txt|exe|pdf|png|jpg)$/i.test(value);

/** The accounts every manual uses as its example, and words that are not names. */
export const USERNAME_NOT = /^(?:admin(?:istrator)?|root|user(?:name)?|guest|test(?:user)?|demo|default|example|anonymous|nobody|postgres|mysql|sa|system|service|operator|ubuntu|ec2-user|centos|pi|jenkins|git|www-data|none|null|required|optional|string|your[_-]?\w*|my[_-]?\w*)$/i;

/**
 * A driving licence or passport number under its label in the benchmark's
 * languages, or a few words from it: "Förarbrevsnummer: QA37887457",
 * "Numéro de permis de conduire : Z11-4940-613-60", "licencia de conducir de
 * Monique C. Morel, T50-5824-939-67", "Pasaporte (número: 123456789",
 * "driver's license number on file is N61285039", "Passnummer (N93588207)".
 * The value needs a digit, and the words in between may not contain one, a
 * full stop or a line break.
 */
const ID_DOC_LABEL = String.raw`(?:carte\s+(?:nationale\s+)?d['’]identit[ée]|num[ée]ro\s+d['’]identi(?:t[ée]|fication)|pi[èe]ce\s+d['’]identit[ée]|(?:personal)?ausweis(?:nummer)?|id-nummer|numero\s+di\s+identificazione|numero\s+(?:della\s+)?carta\s+d['’]\s?identit[àa]|documento\s+(?:nacional\s+)?de\s+identidad|n[úu]mero\s+de\s+identificaci[óo]n|c[ée]dula(?:\s+de\s+identidad)?|identiteitsnummer|identiteitskaart(?:nummer)?|f[öo]rarbrevsnummer|k[öo]rkortsnummer|k[öo]rkort|licencia\s+de\s+conduc(?:ir|tor)|permiso\s+de\s+conducir|permis\s+de\s+conduire|patente\s+di\s+guida|rijbewijs(?:nummer)?|f[üu]hrerschein(?:nummer)?|driver['’]?s?[\s_\\-]*licen[cs]e(?:[\s_\\-]*(?:number|no\.?|num))?|driving[\s_\\-]*licen[cs]e(?:[\s_\\-]*(?:number|no\.?))?|pass(?:port)?nummer|reisepass(?:nummer)?|pasaporte|passeport|passaporto|paspoort(?:nummer)?|passport(?:[\s_\\-]*(?:number|no\.?|num))?|passnr\.?)`;
/**
 * A national, tax, insurance or record number under the name its country
 * gives it, in a sentence: "hetu 280801A537K", "f.nr. 03024812678", "OIB
 * 85920417336", "ΑΦΜ: 128475930", "CURP: HELG890412MDFRPD07", "SIRET 812 345
 * 678 00021", "NIK sy 3174052304910003", "マイナンバー5520 1187 3346", "رقم
 * الهوية: 1145678923", "ת״ז 312456789". The lists above are English and
 * German; these are the rest of the forty languages (realistic5). A space
 * inside the number only before a digit, so "CURP: … RFC: …" stays two
 * numbers, and the scan asks for five digits or more.
 */
/**
 * And the IDs with a check digit of their own: under their label, a number
 * that fails its check is still the person's number, mistyped or invented
 * for the message, so it is hidden too (realistic5: "TC KİMLİK NO:2846…",
 * "CNP: 1720…", "Personnr:1987…", "身分證字號：F128…", "Số CCCD: 0791…").
 */
/**
 * The short labels forms put before an ID: Portugal's CC (cartão de
 * cidadão), Brazil's RG, CTPS and SUS card, Czechia and Slovakia's OP,
 * Romania's CI and the Philippines' TIN: "CC:11843027 4 ZY8", "cartão do SUS
 * 898 0012 3456 7801", "Seria și nr. CI: TZ 482915", "OP: 209481736", "Ang TIN
 * ng asawa ko ay 221-908-455-000" (realistic5, 2026-10-25). In capitals
 * only, and the scan asks for five digits, so an email's "CC:" with an
 * address after it is not taken.
 */
// Capitals stay capitals under anyCase, which adds only the capital of a small letter.
// A space, a colon or "nº" after the short ones, never a value run into
// them: "RG01420XB" and a signature's "CC66 70E6" are other things.
const WORLD_ID_LABEL_SHORT = String.raw`(?:CC|RG|OP|CI|TIN|CTPS)(?=[ \t]*[:：]|[ \t]+(?:n[º°]|\d))|(?:TIN|OP)(?=(?:[ \t]+[^\s\d:：,.]+){1,3}[ \t]+(?:je|ay|adalah)[ \t])|IG(?=[ \t]?\d{10,11}(?!\d))|cart[ãa]o[ \t]+(?:do[ \t]+)?SUS|nr\.?[ \t]+CI`;
const WORLD_ID_LABEL_MORE = String.raw`tc[ \t]+k[iİı]ml[iİı]k(?:[ \t]+(?:no|numaram|numaras[ıi]))?|tc(?=[ \t]*\d{11}(?!\d))|personnr\.?|pers\.?[ \t]?nr\.?|personnummer|身分證字號|身分证号?|s[ốo][ \t]+cccd|cccd|cmnd|cnp|nr\.?[ \t]+dowodu|numer[ \t]+dowodu|dow[óo]d[ \t]+osobisty|[čc][íi]slo[ \t]+op|паспорт|снилс|(?:полис[ \t]+)?омс|nik|ת״ז|ת"ז|מס׳[ \t]+זהות|מס'[ \t]+זהות|תעודת[ \t]+זהות|niss|n\.?º[ \t]+de[ \t]+utente(?:[ \t]+sns)?|contribuinte(?:[ \t]+n\.?º)?|philhealth(?:[ \t]+no\.?)?|pag-ibig(?:[ \t]+mid)?|sss(?:[ \t]+no\.?)?|emirates[ \t]+id|هوية[ \t]+إماراتية(?:[ \t]+رقم)?|เลขประจำตัวประชาชน|เลขบัตรประชาชน|เลขประกันสังคม(?:หนู|ผม|ของ(?:ฉัน|ผม|หนู))?|เลข(?:ประจำตัว)?ผู้เสียภาษี|ஆதார்(?:[ \t]+எண்)?|steuer-?id|steueridentifikationsnummer|svnr|sv-?nummer|sozialversicherungsnummer|rentenversicherungsnummer|inn(?=[ \t]*=)|תעודת[ \t]+ה?זהות|کد[ \t]+ملی|kitambulisho|RUT|این[ \t]+ٹی[ \t]+این|${WORLD_ID_LABEL_SHORT}`;
const WORLD_ID_LABEL = String.raw`(?:hetu|henkil[öo]tunnus|f\.?[ \t]?nr\.?|fnr\.?|f[øo]dselsnummer|pesel|oib|mbo|rodn[ée][ \t]+[čc][íi]slo|r\.?[ \t]?č\.?|i[čc]o|di[čc]|αφμ|α\.?φ\.?μ\.?|αμκα|α\.?μ\.?κ\.?α\.?|α\.?δ\.?τ\.?|αρ\.?[ \t]+ταυτ[όο]τητας|ad[óo]sz[áa]m|ad[óo]azonos[íi]t[óo](?:[ \t]+jel)?|taj(?:[ \t]*sz[áa]m)?|szem[ée]lyi[ \t]+igazolv[áa]ny(?:[ \t]+sz[áa]ma)?|npwp|ktp|curp|rfc|cuit|cuil|cpf|cnpj|siret|siren|nin|bvn|bsn|burgerservicenummer|versichertenn(?:r\.?|ummer)|kvk(?:-?nummer)?|cpr(?:-?n(?:r\.?|ummer))?|dni|nie|nif|tc[ \t]+kimlik(?:[ \t]+no)?|gstin|uhid|ipp|matricola|matricule|personeelsnummer|no\.?[ \t]+rekam[ \t]+medis|rekam[ \t]+medis|expediente|cartella(?:[ \t]+clinica)?|hospital[ \t]+no\.?|egn|инн|マイナンバー|個人番号|カルテ番号|患者番号|社員番号|병록번호|사번|주민등록번호|身份证号码?|رقم[ \t]+الهوية|الرقم[ \t]+القومي|(?:ال|لل)بطاقة[ \t]+الوطنية(?:[ \t]+رقم)?|cip|osobn[ae][ \t]+iskaznic[ea]|ob[čc]ianskeho[ \t]+preukazu|єдрпоу|едрпоу|декларац(?:ія|ії)|الرقم[ \t]+الضريبي|עוסק[ \t]+מורשה|এনআইডি|জন্ম[ \t]+নিবন্ধন[ \t]+নং|রেজি\.?[ \t]+নং|आधार(?:[ \t]+(?:नंबर|संख्या))?|कर्मचारी[ \t]+कोड|${WORLD_ID_LABEL_MORE})`;
// The label in either case with anyCase, not the i flag, under which \p{Lu}
// also matches a lower-case letter and "cartella clinica è 756…" took the è.
// Not here: MRN, whose prefix RECORD_ID_PREFIXED_PATTERN takes whole
// ("MRN-321180").
/**
 * A customer, employee or patient number under the name the other languages
 * give it: "numéro client CL-0098341", "ügyfélszám UA-3381042", "núm.
 * d'empleat E-7731", "matrícula 004512", "社員番号S-10382", "工号HR-30126",
 * "mã bệnh nhân BN-2026-118734", "病历号：ZY20250418093", "住院号2025-031877",
 * "رقم الملف MRN-2026-558410" (realistic5, 2026-10-25).
 * And "zákaznické číslo", "osobní číslo", "törzsszám", "matični broj",
 * "αριθμός μητρώου", "מספר לקוח", "الرقم الوظيفي", "कस्टमर आईडी", "no pelanggan",
 * "お客様番号", "会员号", "員編", and patient and member numbers: "Patientennummer",
 * "número de historia", "nr historii choroby", "No. RM", "Mitgliedsnummer",
 * "n° adhérent", "tessera n.", "lidnummer", "broj člana" (realistic6 and realistic7
 * misses, read 2026-11-11). CUSTOMER_ID_CUED_PATTERN
 * has the English. The value is capitals and digits; the scan asks for three
 * digits with letters, or four alone, and not a year or a date.
 */
const WORLD_RECORD_LABEL = String.raw`(?:z[áa]kazn[íi]ck[ée]\s+[čc][íi]slo|[čc][íi]slo\s+klienta|broj\s+[čc]lana|nr\.?\s+klienta|numer\s+klienta|nr\.?\s+client|patientennummer|patient(?:en)?-?nr\.?|pati[ëe]ntnummer|patient\s+no\.?(?:\s+niya\s+ay)?|n[úu]mero\s+de\s+historia(?:\s+cl[íi]nica)?|nr\.?\s+historii\s+choroby|n[úu]mero\s+de\s+utente|n\.?º\s+(?:de\s+)?(?:utente|SNS)|tarjeta\s+sanitaria|no\.?\s+RM|m[ãa]\s+BN|mitgliedsnummer|mitglieds-?nr\.?|n°\s*(?:d['’]\s?)?adh[ée]rent|num[ée]ro\s+(?:d['’]\s?)?adh[ée]rent|tessera(?:\s+n\.?)?|lidnummer|lidmaatschapsnummer|account\s+ref(?:erence)?|osobn[íiée]\s+[čc][íi]slo|t[öo]rzssz[áa]m|mati[čc]ni\s+broj|αριθμ[οό]ς\s+μητρ[ωώ]ου|n[úu]m\.?\s+(?:de\s+)?client|client\s+n[úu]m\.?|no\.?\s+pelanggan|no\.?\s+pekerja|κωδικ[οό]ς\s+πελ[αά]τη|αριθμ[οό]ς\s+πελ[αά]τη|num[ée]ro\s+(?:de\s+)?client|n°\s*client|korisni[cč]ki\s+broj|broj\s+korisnika|[üu]gyf[ée]lsz[áa]m|cod(?:ul)?\s+client|num[aă]r\s+(?:de\s+)?client|[čc][íi]slo\s+z[áa]kazn[íi]ka|klantnummer|kundnummer|kundenummer|kundennummer|asiakasnumero|m[ãa]\s+kh[áa]ch\s+h[àa]ng|nomor\s+pelanggan|id\s+pelanggan|m[üu][şs]teri\s+no|numer\s+klienta|номер\s+клиента|номер\s+клієнта|n[úu]m\.?\s+d['’]empleat|n[úu]mero\s+de\s+empleado|num[ée]ro\s+d['’]employ[ée]|matr[íi]cula|matricola|n\.?º\s+mecanogr[áa]fico|personalnummer|medarbejdernummer|ansattnummer|anst[äa]llningsnummer|ty[öo]ntekij[äa]numero|NIP|sicil\s+no|personel\s+no|m[ãa]\s+NV|m[ãa]\s+nh[âa]n\s+vi[êe]n|numer\s+pracownika|табельн(?:ый|ий)\s+номер|employee\s*(?:id|code)|emp\.?\s*id|staff\s+id|no\.?\s+registrasi(?:\s+rawat\s+inap)?|n[ºo°]\.?\s+do\s+prontu[áa]rio|prontu[áa]rio|m[ãa]\s+b[ệe]nh\s+nh[âa]n|s[ốo]\s+v[àa]o\s+vi[ệe]n|HN)`;
const WORLD_RECORD_LABEL_UNSPACED = String.raw`(?:환자\s*번호(?:는|은)?|מספר\s+(?:לקוח|עובד)|الرقم\s+الوظيفي|رقم\s+الموظف|कस्टमर\s+आईडी|کسٹمر\s+آئی\s+ڈی|கஸ்டமர்\s+ஐடி|కస్టమర్\s+ఐడీ|ఉద్యోగి\s+ఐడీ|お客様番号|会员号|會員號|員編|员编|מס['׳]?\s*לקוח|رقم\s+العميل|رقم\s+الملف|顧客番号|客户编号|客戶編號|社員番号|職員番号|工号|工號|員工編號|病历号|病歷號碼?|住院号|住院號|病案号|診察券番号|고객\s*번호|환자\s*번호|รหัสลูกค้า|รหัสพนักงาน|कर्मचारी\s+(?:कोड|आईडी|संख्या)|ملازم\s+کوڈ|ایم\s+آر\s+نمبر|ఎంప్లాయీ\s+ఐడీ|పేషెంట్\s+ఐడీ|అడ్మిషన్\s+నం\.?|அனுமதி\s+எண்|ஊழியர்\s+எண்|কর্মচারী\s+আইডি|আইডি)`;
export const WORLD_RECORD_ID_PATTERN = new RegExp(
  String.raw`(?:(?<![\p{L}\p{N}])${anyCase(WORLD_RECORD_LABEL)}(?![\p{Script=Latin}\p{Script=Greek}\p{Script=Cyrillic}])|${WORLD_RECORD_LABEL_UNSPACED})` +
  String.raw`[ \t]*(?:(?:[:：#=]|${anyCase(String.raw`no\.?|nº|n°|nr\.?|je|est|es|é|è|ist|là|ay`)}|是|は)[ \t]*)*\(?` +
  String.raw`(?=[A-Z0-9/-]*\d)([A-Z0-9](?:[A-Z0-9/-]|[ ](?=\d{2})){2,22}[A-Z0-9])(?![\p{Script=Latin}\p{N}])`,
  "gdu",
);

/**
 * An insurance policy or claim number under its label, in the languages
 * the realistic sets write in: "Schadennummer SKV-26-0093371", "n° de sinistre
 * MDF-26-118374", "sinistro n. MAT-26-552019", "broj štete ST-2026-0881734",
 * "nr szkody SZK/2026/0441927", "číslo škodní události PU-2026-5518043",
 * "pòlissa és PL-40917283", "número da apólice é AP-55190287", "No. Polis:
 * MV-SBY-25-0093821", "по полису ГП-2025-0418833", "συμβόλαιο ΑΠ-3381927",
 * "פוליסה MN-4471206", "証券番号TK-77310482", "사고번호 KB-2026-1047731"
 * (realistic6 and realistic7 misses, read 2026-11-11). A policy and a claim
 * belong to a person the way an account does. The value is capitals in any
 * script, digits, hyphens and slashes; the scan asks for four digits and
 * turns down a year or a date. An order or a case number is not a policy:
 * none of these labels names one.
 */
const INSURANCE_LABEL = String.raw`(?:claim\s+(?:no\.?|number|ref(?:erence)?)|schaden-?(?:nummer|nr\.?)|schadenummer|skadenummer|skadenr\.?|(?:num[ée]ro|n°)\s+de\s+sinistre|sinistre|sinistro|n[úu]mero\s+de\s+siniestro|siniestro|broj\s+[šs]tete|n(?:ume)?r\.?\s+szkody|[čc][íi]slo\s+(?:[šs]kodn[íi]|poistnej)\s+ud[áa]losti|dosar\s+daun[ăa]|p[òo]lissa|ap[óo]lice|polizza|p[óo]liza|polisa|polis(?:i|e)?|pojistk[ay]|poistk[ay]|policennummer|полис[ауеы]?|συμβ[οό]λαι[οα]|ασφαλιστ[ηή]ριο)`;
const INSURANCE_LABEL_UNSPACED = String.raw`(?:פוליס(?:ה|ת)|証券番号|證券番号|保険証券番号|사고\s*번호|증권\s*번호|पॉलिसी(?:\s*(?:नं\.?|नंबर|संख्या))?|পলিসি(?:\s*(?:নং|নম্বর))?|بوليصة|رقم\s+(?:الوثيقة|البوليصة|المطالبة))`;
export const INSURANCE_ID_PATTERN = new RegExp(
  String.raw`(?:(?<![\p{L}\p{N}])${anyCase(INSURANCE_LABEL)}(?![\p{L}])|${INSURANCE_LABEL_UNSPACED})` +
  String.raw`[ \t]*(?:(?:[:：#=]|${anyCase(String.raw`no\.?|nº|n°|nr\.?|n\.|num\.?|je|est|es|és|é|è|ist|is|er|är|č\.`)}|是|は)[ \t]*)*\(?` +
  String.raw`(?=[\p{Lu}0-9/-]*\d)([\p{Lu}0-9](?:[\p{Lu}0-9/-]|[ ](?=\d)){2,24}[\p{Lu}0-9])(?![\p{L}\p{N}])`,
  "gdu",
);

/**
 * An identity, licence, passport or tax number under its Chinese, Japanese
 * or Korean label, whatever its shape: "身份证号为CZKRIQSCUV", "驾驶证号
 * V31KOCTZSA", "운전면허번호: GUS7COFNAZ", "주민등록번호(대체): MWKJQXP1LG",
 * "税務番号（任意）: 482165051067" (moreLanguages practice half, 2026-11-02).
 * WORLD_ID_LABELLED_PATTERN asks for five digits; under one of these labels
 * a run of capitals is the number too.
 */
const CJK_ID_LABEL = String.raw`(?:身份证(?:号码|号)|身份證(?:號碼|號|字號)|证件号码?|證件號碼?|驾驶证号码?|驾照号码?|驾驶执照号码?|护照号码?|護照號碼?|纳税人识别号|税号|社保号|社会保障号码?|운전면허(?:증)?[ \t]?번호|주민등록[ \t]?번호|여권[ \t]?번호|사회보장[ \t]?번호|외국인등록[ \t]?번호|신분증[ \t]?번호|運転免許(?:証)?番号|免許証番号|マイナンバー|個人番号|税務番号|納税者番号|パスポート番号|旅券番号|在留カード番号|社会保障番号)`;
export const CJK_ID_LABELLED_PATTERN = new RegExp(
  String.raw`${CJK_ID_LABEL}(?:[ \t]*[（(][^）)\n]{1,6}[）)])?(?:\*\*)?[ \t]*(?:[:：]|为|為|是|は|는|은)?[ \t]*[（(]?[ \t]*([A-Z0-9](?:[A-Z0-9-]){4,22}[A-Z0-9])(?![A-Za-z0-9])`,
  "gdu",
);

export const WORLD_ID_LABELLED_PATTERN = new RegExp(
  // A word boundary in front only where words have one: "夫のマイナンバー5520…".
  // A Latin, Greek or Cyrillic label may not run on into a word of its
  // script; a Han one runs into its value ("身分證字號H124598033"). A
  // relative's word may follow a Hebrew label: "ת״ז האם 301928374". Up to
  // three words may stand between a label and the verb that gives its value:
  // "Broj osobne iskaznice opunomoćitelja je 114582037", "Číslo OP
  // splnomocniteľa je EA482215", "El meu NIE és Y2847193B" (realistic5).
  String.raw`(?<![\p{Script=Latin}\p{Script=Greek}\p{Script=Cyrillic}\p{N}])${anyCase(WORLD_ID_LABEL)}(?!(?<=[\p{Script=Latin}\p{Script=Greek}\p{Script=Cyrillic}])[\p{Script=Latin}\p{Script=Greek}\p{Script=Cyrillic}])(?:(?:[ \t]+\p{Ll}[\p{Ll}\p{M}'’]*){1,3}(?=[ \t]+(?:je|és|es|é|è|ay|is|adalah|ist|est|är|er|on|là)[ \t]))?[ \t]*(?:(?:${anyCase(String.raw`no\.?|nº|n°|nr\.?|number|num|sy|saya|is|è|é|es|és|est|ist|je|er|är`)}|(?:${anyCase(String.raw`ay|adalah|là`)})(?=[ \t])|是|為|为|האם|האב|שלי|שלו|שלה|:|：|=|#|[-–](?=[ \t]))[ \t]*)*([\p{Lu}\d](?:[\p{Lu}\d./-]|[ ](?=\d|\p{Lu}[ ]\d))*[\p{Lu}\d])(?![\p{Script=Latin}\p{Script=Greek}\p{Script=Cyrillic}\p{N}])`,
  "gud",
);

/**
 * A form copied flat, its fields run together with nothing between them:
 * "Name:Olumide AdebayoNIN:48291037615 Address:…", "Namn:Hedvig
 * SjöbergPersonnr:19870619-2240", "Nombre:Iñaki BerasateguiDNI:93863956JTeléfono"
 * (realistic5, and the ID practice set of 2026-10-26). The label is glued to
 * the word before it, so WORLD_ID_LABELLED_PATTERN, which wants a word
 * boundary, never sees it; and the value is glued to the next field's name.
 *
 * So only this shape: a label that opens with a capital right after a small
 * letter, a colon, and a value that stops where the next field begins — a
 * capitalised word ("Teléfono", "Ville", "Comune") or a label of its own
 * ("RG:", "DOB:", "TAJ szám:"). Shortest first, so "CE111775BDOB:" keeps its
 * B: the next field is "DOB", which is a label, and "BDOB" is not.
 */
const GLUED_ONLY_LABEL = String.raw`NI[ \t]+no\.?|NI[ \t]+number|N°[ \t]+s[ée]cu|Steuer-?ID|CF|SSN|DL|NRIC|FIN|No\.?[ \t]+KP|PhilSys|Namba[ \t]+ya[ \t]+NIDA|NIDA|Cart[ãa]o[ \t]+de[ \t]+Cidad[ãa]o|SVNR|ஆதார்`;
const GLUED_NEXT_LABEL = String.raw`(?:${anyCase(WORLD_ID_LABEL)}|${GLUED_ONLY_LABEL}|D\.?O\.?B\.?|DOB)[ \t]*[:：]`;
export const GLUED_FORM_ID_PATTERN = new RegExp(
  String.raw`(?<=[\p{Ll}\p{M}\p{N}])(?=\p{Lu})(?:${anyCase(WORLD_ID_LABEL)}|${GLUED_ONLY_LABEL})[ \t]*[:：][ \t]*` +
  // A space inside the value before a digit, or before the letters and digit
  // that end a Portuguese citizen card ("14538702 4 ZX8").
  String.raw`([\p{Lu}\d](?:[\p{Lu}\d./-]|[ ](?=\d|\p{Lu}{1,2}\d))*?[\p{Lu}\d])` +
  String.raw`(?=\p{Lu}\p{Ll}|${GLUED_NEXT_LABEL}|[^\p{L}\p{N} ./-]|[ ](?!\d|\p{Lu}{1,2}\d)|[./-](?!\d)|$)`,
  "gdu",
);

/**
 * A label, a few words of hedging, and then the number: "Steuer-ID ist,
 * glaube ich, die 83 104 572 965", "NIF, salvo erro, é o 248 117 093", "BSN
 * is volgens mij 304810903", "СНИЛС вроде 191-533-762 79", "身分證字號應該是
 * P188863346", "NIK saya kayaknya 3273…" (ID practice set, 2026-10-26).
 * WORLD_ID_LABELLED_PATTERN allows only the verb, so these went as written.
 *
 * Forty characters at most between, none of them a digit, a line break or the
 * end of a sentence, so the number is the next one the person writes after
 * naming it; and seven digits at least, where the labelled scan asks five,
 * because the words between could be saying anything.
 */
export const WORLD_ID_NEAR_PATTERN = new RegExp(
  String.raw`(?<![\p{Script=Latin}\p{Script=Greek}\p{Script=Cyrillic}\p{N}])${anyCase(WORLD_ID_LABEL)}(?!(?<=[\p{Script=Latin}\p{Script=Greek}\p{Script=Cyrillic}])[\p{Script=Latin}\p{Script=Greek}\p{Script=Cyrillic}])` +
  // Not a label joined to its number ("UHID-4410287"): that is one token,
  // and the record scans take it whole.
  String.raw`(?![-_/])[^\d\n.!?。！？]{1,40}?(?<![\p{Script=Latin}\p{Script=Greek}\p{Script=Cyrillic}\p{N}])` +
  String.raw`([\p{Lu}\d](?:[\p{Lu}\d./-]|[ ](?=\d|\p{Lu}[ ]\d))*[\p{Lu}\d])(?![\p{Script=Latin}\p{Script=Greek}\p{Script=Cyrillic}\p{N}])`,
  "gdu",
);

export const ID_DOC_CUED_PATTERN = new RegExp(
  String.raw`\b${ID_DOC_LABEL}(?:[^\n.\d]{0,40}?)(?<![A-Za-z0-9-])(?=[A-Za-z-]*\d)([A-Za-z0-9](?:[A-Za-z0-9-]{4,18})[A-Za-z0-9])(?![A-Za-z0-9-])`,
  "gid",
);

/**
 * A routing or bank code under its label in the benchmark's languages:
 * "Numéro de routage bancaire: 310083082", "din bankruttningsnummer är
 * 924775161", "Bankleitzahl: 98316462". ACCOUNT_CUED_PATTERN has the English.
 */
export const ROUTING_CUED_INTL_PATTERN =
  /\b(?:num[ée]ro\s+de\s+routage(?:\s+bancaire)?|code\s+de\s+routage|bankruttningsnummer|clearingnummer|bankleitzahl|blz|n[úu]mero\s+de\s+ruta|c[óo]digo\s+de\s+ruta|numero\s+di\s+routing|routingnummer|aba[\s_\\-]*(?:number|no\.?|routing(?:\s+number)?)|bank[\s_\\-]*routing[\s_\\-]*(?:number|no\.?))\b(?:[ \t]+(?:for|of|on)[ \t]+[a-z][a-z \t]{0,30}?(?=[ \t]*:))?(?:\s*(?:is|es|est|ist|är|è|being|:|=|#|["'*]))*\s*(?<!\d)(\d{8,9}|\d{3}[ -]\d{3}[ -]\d{2,3})(?!\d)/gid;
// "bank routing number being 631025874", "routing number for any direct
// deposits: 211302587" (Nemotron practice rows, 2026-10-08).

/**
 * A date of birth whose label and date have a few words between them, as
 * forms write it: "Datum der Geburt (Date of Birth): 27.08.1963", "Date de
 * naissance de l'expéditeur : 26/07/1925", "Geboortedatum aannemer:
 * 2020-08-27", "**Date of Birth:** 24th October 1961", "<DateOfBirth>1919-11-29".
 * DOB_CUED_PATTERN allows "is", a colon or "on"; this allows up to forty
 * characters without a digit, a full stop, a semicolon or a line break,
 * turned down when the words say the date is something else ("date of birth
 * is required; the deadline is 12/05/2024").
 */
const DOB_NOT = String.raw`(?:due|deadline|expir|issued?|valid|until|since|before|after|updated|signed|submitted|received|effective|emitid|expedici|ausgestellt|d[ée]livr|rilasci|utf[äa]rd|verloop|g[üu]ltig)`;
export const DOB_LABELLED_PATTERN = new RegExp(
  String.raw`(?:\b(?:date[\s_]*of[\s_]*birth|dateofbirth|birth[\s_]*date|d\.?o\.?b\.?|geburtsdatum|datum\s+der\s+geburt|fecha\s+de\s+nacimiento|date\s+de\s+naissance|data\s+di\s+nascita|geboortedatum|f[öo]delsedatum|f[öo]delsedag|syntym[äa]aika)(?![\p{L}\d_]))` +
  String.raw`(?:(?!${DOB_NOT})[^\n.;\d]){0,40}?(?<![\p{L}\d])(${DOB_DATE})`,
  "gidu",
);

/**
 * A MAC address: six pairs of hex, one separator used throughout. It names a
 * device, and a device names its owner as well as a phone number does.
 */
export const MAC_ADDRESS_PATTERN = /(?<![0-9A-Fa-f:.-])(?:[0-9A-Fa-f]{2}([:-])[0-9A-Fa-f]{2}(?:\1[0-9A-Fa-f]{2}){4}|[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4})(?![0-9A-Fa-f:-])(?!\.[0-9A-Fa-f])/g;

/**
 * The machine-readable zone of a passport: two lines of 44 characters. The
 * first carries the holder's name ("P<UTOERIKSSON<<ANNA<MARIA<<<"), the second
 * the passport number, nationality, date of birth and expiry. Nothing else is
 * written in that alphabet at that length.
 */
export const PASSPORT_MRZ_PATTERN =
  /(?<![A-Z0-9<])(?:P[A-Z<][A-Z<]{3}[A-Z<]{39}|[A-Z0-9<]{9}[0-9<][A-Z<]{3}\d{6}[0-9<][MFX<]\d{6}[0-9<][A-Z0-9<]{14}[0-9<]{2})(?![A-Z0-9<])/g;

/**
 * National identity numbers that carry their own proof.
 *
 * A bare number is not evidence of anything — that is the rule this file
 * keeps everywhere else. These are the exceptions, for the same reason a
 * card number is: each has a check digit, a checksum or an embedded date
 * that findStructured verifies, so a random figure passes about one time in
 * ten to one in a thousand, and the shapes themselves are unusual. The cases
 * come from Microsoft Presidio's recognizer tests (MIT), which is where the
 * checks and their test values are published.
 *
 *   ES_ID       Spanish DNI/NIF and NIE: 8 digits and a mod-23 letter
 *   FI_HETU     Finnish henkilötunnus: DDMMYY, century sign, mod-31 check
 *   SE_PNR      Swedish personnummer: (century) YYMMDD-NNNN, Luhn
 *   PL_PESEL    Polish PESEL: 11 digits, weighted check, date inside
 *   TR_TCKN     Turkish kimlik no: 11 digits, two check digits
 *   TH_TNIN     Thai national ID: 13 digits, mod-11 check
 *   KR_RRN      Korean resident and foreigner numbers: YYMMDD-GNNNNNN, check
 *   ZA_ID       South African ID: YYMMDD, seven digits, Luhn; or a Romanian CNP
 *   ELEVEN      also Greek AMKA, Norwegian fødselsnummer, Estonian and Lithuanian
 *               personal codes, a Belgian national number: each a date and a check
 *   IN_AADHAAR  12 digits in fours, Verhoeff check
 *   ZA_ID       South African ID: YYMMDD, 7 digits, Luhn
 *   AU_MEDICARE 10 digits spaced 4-5-1, weighted check. Written unbroken it is
 *               just ten digits, which the Medicare cue still finds
 *   GROUPED_ID  nnn nnn nnn: Canadian SIN (Luhn) or Australian TFN (weighted)
 *
 * The digit-only forms also need a clean edge on both sides: "2123456702AF"
 * is a part number with a Medicare number's digits in it, and "+48 512 345
 * 678" is a Polish mobile whose last nine digits pass a Canadian SIN's Luhn
 * check — a group that follows a "+" or another group is part of something
 * longer.
 *
 * And the ones whose shape is proof enough on its own:
 *
 *   IN_PAN       five letters, four digits, a letter; fourth letter a holder type
 *   IT_CF        Italian codice fiscale, sixteen characters in a fixed grammar
 *   UK_DL        UK driving licence, sixteen characters with the birth date inside
 *   UK_NINO      National Insurance number with HMRC's letter rules
 *   US_MBI       Medicare Beneficiary Identifier, eleven characters, no S L O I B Z
 *   DE_SVNR      German social security number: area, birth date, initial, serial
 */
/**
 * Written forms that carry their own check digits, from Latin America and
 * Asia: Brazil's CPF (000.000.000-00) and CNPJ (00.000.000/0000-00), Chile's
 * RUT (00.000.000-K, or 0000000-K), Mexico's CURP (eighteen characters with a birth date),
 * Singapore's NRIC/FIN (S1234567D), Hong Kong's HKID (A123456(3)), China's
 * resident ID (eighteen characters, a date inside, ISO 7064 check) and
 * Ireland's PPS number (seven digits and a check letter). Only the punctuated
 * forms for CPF, CNPJ and RUT: eleven or nine bare digits are too often
 * something else, and the cued ID rule still finds them after the name.
 */
export const BR_CPF_PATTERN = /(?<![\w.\/-])\d{3}\.\d{3}\.\d{3}-\d{2}(?![\w\/-])(?!\.\d)/g;
export const BR_CNPJ_PATTERN = /(?<![\w.\/-])\d{2}\.\d{3}\.\d{3}\/\d{4}-\d{2}(?![\w\/-])(?!\.\d)/g;
export const CL_RUT_PATTERN = /(?<![\w.\/-])(?:\d{1,2}\.\d{3}\.\d{3}|\d{7,8})-[\dkK](?![\w\/-])(?!\.\d)/g;
export const MX_CURP_PATTERN = /\b[A-Z][AEIOUX][A-Z]{2}\d{6}[HMX][A-Z]{2}[B-DF-HJ-NP-TV-Z]{3}[0-9A-Z]\d\b/g;
export const SG_NRIC_PATTERN = /\b[STFGM]\d{7}[A-Z]\b/g;
export const HK_ID_PATTERN = /\b[A-Z]{1,2}\d{6}\([0-9A]\)/g;
export const CN_RIC_PATTERN = /(?<![\w+-])[1-9]\d{16}[\dXx](?![\w-])/g;
export const IE_PPS_PATTERN = /\b\d{7}[A-W][ABHWTX]?\b/g;
/**
 * Four more from python-stdnum's lists, each with its own check: France's
 * NIR (sex, year, month, département — 2A and 2B for Corsica — commune,
 * serial, a mod-97 key), the Czech and Slovak rodné číslo as written with its
 * slash, Portugal's Cartão de Cidadão (eight digits, a digit, two letters, a
 * digit), and Mauritius's NID (a letter, twelve digits with the birth date,
 * a mod-17 check character).
 */
export const FR_NIR_PATTERN = /(?<![\w+-])[12] ?\d{2} ?(?:0[1-9]|1[0-2]|[2-9]\d) ?(?:\d{2}|2[AB]) ?\d{3} ?\d{3} ?\d{2}(?![\w-])(?![ -]\d)/g;
export const CZ_RC_PATTERN = /(?<![\w\/.-])\d{6}\/\d{3,4}(?![\w\/-])(?!\.\d)/g;
export const PT_CC_PATTERN = /\b\d{8} ?\d ?[A-Z]{2} ?\d\b/g;
/** Belgium's national number as printed on the card: YY.MM.DD-SSS.CC, mod 97. */
export const BE_NN_PATTERN = /(?<![\w.-])\d{2}\.\d{2}\.\d{2}-\d{3}\.\d{2}(?![\w-])(?!\.\d)/g;
/** Malaysia's MyKad (YYMMDD-PB-NNNN) and Pakistan's CNIC (NNNNN-NNNNNNN-N), as printed with their dashes. */
export const MY_NRIC_PATTERN = /(?<![\w-])\d{6}-\d{2}-\d{4}(?![\w-])/g;
export const PK_CNIC_PATTERN = /(?<![\w-])\d{5}-\d{7}-\d(?![\w-])/g;
export const MU_NID_PATTERN = /\b[A-Z]\d{12}[0-9A-Z]\b/g;
export const ES_ID_PATTERN = /\b(?:[XYZ][ -]?\d{7}|\d{7,8})[ -]?[A-HJ-NP-TV-Z]\b/g;
/** A foreigner's NIE typed in lower case, "x-2482300w": only with its prefix letter. */
export const ES_NIE_LOWER_PATTERN = /\b[xyz][ -]?\d{7}[ -]?[a-hj-np-tv-z]\b/g;
export const FI_HETU_PATTERN = /\b\d{6}[-+A-FU-Y]\d{3}[0-9A-FHJ-NPR-Y]\b/gi;
export const SE_PNR_PATTERN = /\b(?:(?:18|19|20)\d{6}[-+]?\d{4}|\d{6}[-+]\d{4})\b/g;
export const ELEVEN_DIGITS_PATTERN = /(?<![\w+-])(?<!\d[ -])\d{11}(?![\w-])(?![ -]\d)/g;
export const ZA_ID_PATTERN = /(?<![\w+-])(?<!\d[ -])\d{13}(?![\w-])(?![ -]\d)/g;
export const TH_TNIN_PATTERN = /(?<![\w+-])(?<!\d[ -])[1-8](?:[ -]?\d){12}(?![\w-])(?![ -]\d)/g;
export const KR_RRN_PATTERN = /(?<![\w+-])(?<!\d[ -])\d{6}-?[1-8]\d{6}(?![\w-])(?![ -]\d)/g;
export const IN_AADHAAR_PATTERN = /(?<![\w+:-])(?<!\d[ -])[2-9]\d{3}([ :-]?)\d{4}\1\d{4}(?![\w:-])(?![ -]\d)/g;
export const AU_MEDICARE_PATTERN = /(?<![\w+-])(?<!\d[ -])[2-6]\d{3} \d{5} \d(?: \d)?(?![\w-])(?![ -]\d)/g;
export const GROUPED_ID_PATTERN = /(?<![\w+-])(?<!\d[ -])\d{3}[ -]\d{3}[ -]\d{3}(?![\w-])(?![ -]\d)/g;
export const IN_PAN_PATTERN = /\b[A-Z]{3}[ABCFGHLJPTK][A-Z]\d{4}[A-Z]\b/g;
export const IT_CF_PATTERN = /\b[A-Z]{6}[\dLMNP-V]{2}[ABCDEHLMPRST][\dLMNP-V]{2}[A-Z][\dLMNP-V]{3}[A-Z]\b/g;
export const UK_DL_PATTERN = /\b[A-Z9]{5}\d[0156]\d(?:0[1-9]|[12]\d|3[01])\d[A-Z9]{2}\d[A-Z]{2}\b/g;
export const UK_NINO_PATTERN = /\b(?!BG|GB|KN|NK|NT|TN|ZZ)[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z] ?\d{2} ?\d{2} ?\d{2} ?[A-D]\b/g;
export const US_MBI_PATTERN = /\b[1-9][AC-HJKMNP-RT-Y][AC-HJKMNP-RT-Y\d]\d-?[AC-HJKMNP-RT-Y][AC-HJKMNP-RT-Y\d]\d-?[AC-HJKMNP-RT-Y]{2}\d{2}\b/g;
/** A Philippine UMID / SSS common reference number: twelve digits grouped
 *  4-7-1, a grouping nothing else uses. */
export const PH_CRN_PATTERN = /(?<![\w-])\d{4}-\d{7}-\d(?![\w-])/g;
export const DE_SVNR_PATTERN = /\b\d{2}(?:0[1-9]|[12]\d|3[01])(?:0[1-9]|1[0-2])\d{2}[A-Z]\d{3}\b/g;

/**
 * An ID number with its label after it rather than before: "X1234567 is my
 * passport number", "AAA123456 es mi número de pasaporte". The value must
 * mix letters and digits or be digits, and the label must be an identity
 * document — "ABC123456 is my order number" stays a sentence.
 */
export const ID_LABEL_AFTER_PATTERN =
  /(?<![\w-])([A-Za-z0-9][A-Za-z0-9-]{4,14}[A-Za-z0-9])\s+(?:is|es|est|è|ist)\s+(?:my|mi|mon|ma|mio|mia|mein|meine|his|her|their|our|your|tu|su)\s+(?:(?:driver'?s?\s+)?licen[cs]e|passport|pasaporte|passeport|passaporto|reisepass|n[úu]mero\s+de\s+pasaporte|num[ée]ro\s+de\s+passeport|numero\s+di\s+passaporto|(?:social\s+security|national\s+insurance|tax|id|identity|patient|member|policy)\s+(?:number|no\.?)|ssn|nif|nie|dni)\b/gid;

/**
 * A Japanese postcode: "〒100-0005", or three and four digits beside a place
 * that says it is in Japan ("Tokyo 100-0005", "Chiyoda-ku, Tokyo 100-0005").
 */
export const JP_POSTCODE_PATTERN =
  /(?:〒\s?|(?<=\b(?:Tokyo|Osaka|Kyoto|Yokohama|Nagoya|Sapporo|Fukuoka|Kobe|Sendai|Hiroshima|Japan|[A-Z][a-z]+-(?:ku|shi|ken|cho|machi))\s*,?\s*))(\d{3}-\d{4})(?!\d)/gd;

/**
 * A Japanese address written in Japanese: a prefecture (都道府県), then the
 * city, ward and district in kanji or kana, then the block numbers —
 * "東京都千代田区丸の内1-1-1", "大阪府大阪市北区梅田3-1-3". The prefecture is
 * the anchor; nothing else is written that way.
 */
export const JP_ADDRESS_PATTERN = new RegExp(
  String.raw`(?:東京都|北海道|(?:京都|大阪)府|[\p{Script=Han}]{2,3}県)[\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}ー々]{1,20}?[0-9０-９]{1,4}(?:(?:丁目|番地?|号|[-−－ー])[0-9０-９]{1,4}){0,3}(?:号)?`,
  "gu");

/**
 * The same written in romaji: block numbers, the district, then a ward or
 * city ending in -ku or -shi — "1-1-1 Marunouchi, Chiyoda-ku", "3 Chome-1-1
 * Marunouchi". The -ku is required, which is what keeps "Section 1-1-1" and
 * "Ratio 3-1-1" sentences.
 */
export const JP_ROMAJI_ADDRESS_PATTERN =
  /\b(?:\d{1,2}(?:-\d{1,3}){1,2}|\d{1,2}\s+Chome-\d{1,3}(?:-\d{1,3})?)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?(?=,\s*[A-Z][a-z]+-(?:ku|shi|cho|machi|gun)\b)/g;

export const PRIVATE_IP_PATTERN =
  /(?<!\d)(?<!\d\.)(?:10\.(?:\d{1,3}\.){2}\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3})(?!\d)(?!\.\d)/g;

/**
 * A public IPv4 address under a label that makes it somebody's: a record's
 * "IP Address:" field, "Customer IP", "Login IP", "IP-adress:", "Indirizzo IP:",
 * "IP de acceso:", "from an unknown IP address (55.44.33.22)".
 *
 * Public addresses are otherwise left alone on purpose: in a technical
 * question they are servers ("my server at 52.14.1.9 is down") and the answer
 * needs them. In a customer record, a support ticket or a login log they are a
 * person's connection, which GDPR counts as personal data. So only the label
 * decides, and the scan turns a label down when a word before it says the
 * address is a machine's (server, node, external, gateway, DNS...).
 *
 * The label may also be a table cell ("| Assigned IPv4 | 167.214.85.74"),
 * an XML tag ("<IPv4>203.154.12.195") or end in a comma ("your IPv4,
 * 194.182.100.19"): Nemotron practice rows, 2026-10-08.
 */
export const IP_LABELLED_PATTERN =
  /(?:\b|(?<=_))(?:(?:customer|client|user|visitor|member|login|sign[\s-]?in|source|remote|originating|unknown|suspicious|real|last[\s_-]?login|signup|registration)[\s_-]+)?(?:remote[_-]addr|x[_-](?:forwarded[_-]for|real[_-]ip)|client[_-]?addr(?:ess)?|ip(?:v4)?[\s_-]*(?:address(?:es)?|adress|adres|adresse[sn]?|addr)?|ip-?adresse?|ip-?adress|ip-?adres|indirizzo\s+ip|direcci[óo]n\s+ip|adresse\s+ip|ip\s+de\s+(?:acceso|connexion|conexi[óo]n)|coordonn[ée]es\s+ip)\b(?:\s+(?:is|was|of|:))?[\s:=*"'(|,>]*((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})(?![\d.]*\d)/gid;
/**
 * The second of two addresses under one label: "IP addresses 108.87.25.139
 * and 101.73.200.74". findStructured takes it only when the first was taken
 * under IP_LABELLED_PATTERN. Gretel practice rows (train split, 2026-10-06):
 * the label is written once and the list after it is all one person's.
 */
export const IP_AFTER_IP_PATTERN =
  /(?<![\d.])((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})[ \t]{0,3}(?:,|and|or|&|\/)[ \t]{0,3}(?=((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})(?![\d.]*\d))/gd;

/** Words before an IP label that make the address a machine's, not a person's. */
export const IP_LABEL_MACHINE = /\b(?:server|servers|node|nodes|host|hosts|external|internal|public|static|elastic|floating|virtual|cluster|pod|pods|service|gateway|dns|router|proxy|vpn|endpoint|instance|machine|vm|container|ingress|egress|nat|load[\s-]*balancer|master|worker|api|database|db|bind|listen|listening|our|primary|device|printer|camera|website|site|domain|mail|smtp)[\s_-]*$/i;
/** Addresses every manual uses: example ranges (RFC 5737), loopback, and the well-known public resolvers. */
export const IP_NOT_A_PERSON = /^(?:192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|127\.|0\.|255\.|8\.8\.8\.8$|8\.8\.4\.4$|1\.1\.1\.1$|1\.0\.0\.1$|9\.9\.9\.9$|208\.67\.22[02]\.22[02]$)/;

/** The words that make an address a machine's, wherever they stand. */
const IP_MACHINE_WORD = String.raw`(?:server|servers|node|nodes|host|hosts|external|internal|public|static|elastic|floating|virtual|cluster|pods?|service|gateway|dns|router|proxy|vpn|endpoint|instance|machine|vm|container|ingress|egress|nat|balancer|master|worker|api|database|db|bind|listen|listening|our|primary|device|printer|camera|website|site|domain|mail|smtp)`;

/**
 * A public IPv4 address a few words after its label: "The IP address
 * recorded for this event is 217.134.89.179", "we may collect your IP
 * address, 212.180.5.117", "the user's IP address was recorded as …".
 * IP_LABELLED_PATTERN wants the address straight after the label, and
 * Nemotron's practice rows (2026-10-08) wrote it this way 26 times.
 *
 * Up to five words between, ending in is, was, as, of or be, or a comma
 * straight after the label. None of them, and nothing just before the
 * label, may say the address is a machine's: "the IP address of our
 * server is 52.14.1.9" stays.
 */
export const IP_BRIDGED_PATTERN = new RegExp(
  String.raw`(?<!\b${IP_MACHINE_WORD}[\s_-]{0,3})\b(?:(?:customer|client|user|visitor|member|login|source|remote|originating|unknown|suspicious)[ \t]+)?(?:ip(?:v4)?[ \t]+address(?:es)?|ipv4)` +
  String.raw`(?:,[ \t]*(?:(?:such[ \t]+as|e\.g\.|namely|which[ \t]+(?:is|was))[ \t]+)?|(?:[ \t]+(?!${IP_MACHINE_WORD}\b)[a-z']{1,15}){0,5}?[ \t]+(?:is|was|as|of|be)[ \t]+)` +
  String.raw`((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})(?![\d.]*\d)`,
  "gid",
);

/**
 * An API key said in a sentence: "The API key for accessing the services is
 * tP2nX8jL7mB1kW0hV5Q9c4dUzX2wY6tR", "the api key, which is fQ7w…", "use
 * your unique api key: api_dev_7zKx…". KEY_SPOKEN_PATTERN wants the value
 * straight after "key". Twenty characters at least, and the scan asks for
 * letters and digits, so "the API key is stored in the vault" is prose.
 */
export const API_KEY_SPOKEN_PATTERN =
  /\b(?:api|access|secret|auth(?:entication)?)[ \t]+(?:key|token)(?:[ \t]+(?!(?:example|placeholder|format|like)\b)[a-z]{1,15}){0,5}?(?:[ \t]*[:=]|,[ \t]*which[ \t]+is[ \t]|[ \t]+(?:is|was)[ \t])[ \t]*[*"'`]{0,2}([A-Za-z0-9_-]{20,128})(?![A-Za-z0-9_-])/gid;

/**
 * A cookie said in a sentence: "the http cookie csrf_protection=gk27jxpqz13m",
 * "your http cookie, gdpr_consent=19f3d2b8-…". The pair is taken whole, name
 * and value, as it is written. A value with a digit only: "timezone=Europe/
 * Berlin" is a preference, not a session.
 */
export const COOKIE_SPOKEN_PATTERN =
  /\bcookies?\b[^\n=]{0,40}?[ \t,:]((?<![A-Za-z0-9_])[A-Za-z_][A-Za-z0-9_]{1,40}=(?=[^;\s]{0,200}\d)[A-Za-z0-9._%-]{5,199}[A-Za-z0-9%_-])(?=[;\s,.]|$)/gid;

/**
 * A user name said in a sentence: "Your user name is victormaya", "your
 * username, which is e.thompson", "The user name ka07129 is requesting".
 * USERNAME_LABELLED_PATTERN reads a form's "User Name:" only. Lower case,
 * three to thirty-two characters; with no "is" before it the value must
 * have a digit, a dot or an underscore, and the scan turns down ordinary
 * words and the stock accounts.
 */
export const USERNAME_SPOKEN_PATTERN =
  /\b(?:[Uu]ser[ \t]?[Nn]ame|USERNAME)(?:[ \t]+(is|was)|,[ \t]*(which[ \t]+is))?[ \t]+([a-z][a-z0-9._]{1,30}[a-z0-9])(?![\w@-]|\.\w)/gd;

/**
 * An English verb or adjective ending, for a letters-only value after "user
 * name is": "the username is generated" is a sentence even though "generated"
 * opens with the given name Gene. A real user name built on a name and ending
 * this way ("alfred") has the name at the end, which the scan checks apart.
 */
export const WORD_ENDING_PATTERN = /(?:[td]ed|ated|ized|ised|ing|able|ible|tion|sion|ment|ness|less|ful|ous|ive)$/;

/**
 * A package manager's install line: "winget install 9NQ7512CXL7T",
 * "choco upgrade …". What follows is a catalogue id, not anybody's.
 */
export const PACKAGE_COMMAND_PATTERN =
  /\b(?:winget|choco|scoop|apt(?:-get)?|brew|pip3?|pipx|npm|pnpm|yarn|dnf|yum|zypper|snap|flatpak|cargo|gem|nuget|dotnet[ \t]{1,4}tool)[ \t]{1,4}(?:install|download|upgrade|uninstall|remove|show|info|add|update)[ \t]{1,4}(?:--?[\w-]{1,30}(?:=\S{1,40})?[ \t]{1,4}){0,3}$/;

/** Labels a stand-in keeps rather than replaces: the marker that made the host
 *  internal in the first place, and the public suffix. Keeping both is what
 *  lets the model still reason about it — "this is an internal service" is
 *  useful context and is not the secret. The secret is whose. */
export const HOST_KEEP = new Set([
  ...INTERNAL_MARKERS,
  "com", "net", "org", "io", "co", "uk", "us", "dev", "app", "cloud", "arpa", "home", "svc", "cluster",
]);

export const FAKE_HOST_WORDS = [
  "atlas", "beacon", "cobalt", "delta", "ember", "fjord", "granite", "harbor",
  "indigo", "juniper", "kestrel", "lumen", "meridian", "nimbus", "onyx",
  "pioneer", "quarry", "ridge", "summit", "tundra", "umber", "vertex",
];

/**
 * A run of letters and digits that nobody would type as a word: a password
 * or a token written into a sentence with no label — "use pDI_DYJc7Idx for
 * one-time access", "Remember access codes are: 3742 and x48bCwIKS4nB". Ten to
 * twenty-four characters, standing alone: not inside a URL, an email, a path
 * or a query string. Whether it is random is decided by findStructured
 * (randomToken), not by the shape alone.
 */
export const RANDOM_TOKEN_PATTERN = /(?<![\w@./:\%&=+#-])([A-Za-z0-9_]{10,24})(?![\w@/\%&=+-]|\.\w)/g;

/**
 * A user name made of a person's name: "Roma_Altenwerth", "Joe_Schuster53",
 * "Emmie.Rodriguez72". Joined by an underscore, or by a dot when digits
 * follow — a bare "Object.Keys" is code. findStructured (nameHandle) turns
 * down the ones made of ordinary words: "General_Category", "Energy_Use".
 */
export const NAME_HANDLE_PATTERN = /(?<![\w@./:\%&=+#-])([A-Z][a-z]{1,}(?:_(?:Mc|Mac|O)?[A-Z][a-z]{2,}(?:-[A-Z][a-z]{2,})?\d{0,4}|\.(?:Mc|Mac|O)?[A-Z][a-z]{2,}(?:-[A-Z][a-z]{2,})?\d{1,4}))(?![\w@/\%&=+-]|\.\w)/g;

/**
 * The same with a dot and no number — "Jacques.Schneider", "Herbert.Schulist"
 * — which is also how code names a member ("Console.Write", "Math.Floor").
 * findStructured takes it only when both halves read as a person's: neither
 * an ordinary word nor a term, and not in code.
 */
export const NAME_DOT_PATTERN = /(?<![\w@./:\%&=+#-])((?:Mc|Mac|O)?[A-Z][a-z]{2,}\.(?:Mc|Mac|O)?[A-Z][a-z]{2,}(?:-[A-Z][a-z]{2,})?)(?![\w@/\%&=+(-]|\.\w)/g;

/**
 * A name and a number with no cue at all: "Best, Gaston84", "Contact
 * Creola76 or …". HANDLE_CUED_PATTERN takes it after "username" or "Dear";
 * alone the shape is also "Windows10", "Python3", "Covid19" and "Agent47", so
 * findStructured judges the name.
 */
export const NAME_NUMBER_PATTERN = /(?<![\w@./:\%&=+#$-])([A-Z][a-z]{2,11}\d{1,3})(?![\w@/\%&=+-]|\.\w|[ \t]*\()/g;

/**
 * A user name that is a name and a number — "Moriah59", "Camilla10" — after
 * the words that say it is one: "username is", "your ID", "login", or a
 * greeting ("Dear Norwood61,"). Alone, the shape is also "Windows10" and
 * "Python3", so the cue is the evidence.
 */
export const HANDLE_CUED_PATTERN =
  /(?:\b(?:user\s?name|login(?:\s+name)?|log\s+in\s+as|handle|user\s?id|your\s+id|profile|account\s+name)\b(?:\s+(?:is|was))?\s*[:=]?\s*|\b(?:Dear|Hello|Hi|Hey)\s+)([A-Z][a-z]{2,}(?:\d{1,4}|[._](?:Mc|Mac|O)?[A-Z][a-z]{2,}\d{0,4}))(?![\w@-]|\.\w)/gd;

/**
 * A handle with its @, as Slack, Twitter, Instagram and GitHub write one:
 * "ping @sarahchen on slack", "@sarah.chen", "@ivanov_88". Nothing took it
 * (leak hunt, 2026-11-14). Lower case only, which is how people write them
 * and how Java, Swift and TypeScript do not write their decorators; a Python
 * decorator is followed by "(" or ".name", an npm scope by "/", a version
 * by a digit, an email by a letter in front, a NatSpec tag by its colon
 * ("@custom:predeploy"), and code by what it is welded to (";@x"): a handle
 * in prose follows a space or an opening bracket. What follows the @ is
 * judged by nameHandle, and AT_HANDLE_NOT names the rest: a group mention, a
 * CSS or doc-comment keyword, a dist-tag, a cron shorthand, a domain.
 */
export const AT_HANDLE_PATTERN = /(?<=^|[\s(,\[])@([a-z][a-z0-9_.]{1,29}[a-z0-9])(?![\w@/%&=+:-]|\.\w|\s*\()/gm;
export const AT_HANDLE_NOT = new RegExp(
  "^(?:everyone|channel|here|all|team|group|something|someone|anyone|nothing|anything|everything|custom|media|import|keyframes|supports|layer|page|charset|namespace|font-face|container|scope|property|staticmethod|classmethod|dataclass|abstractmethod|override|param|params|return|returns|type|typedef|see|link|example|deprecated|since|author|version|throws|brief|file|module|abstract|test|before|after|mock|inject|bean|component|service|input|output|latest|next|canary|beta|alpha|rc|dev|stable|nightly|main|master|hourly|daily|weekly|monthly|yearly|annually|reboot|midnight|include|define|interface|implementation|end|synthesize|selector|protocol|optional|required|class|public|private|protected|objc|available|escaping|state|binding|published|environment|generated|preview|apply|tailwind|guest|support|admin|user|bot|me|you|home|login|signup|register|contact|about|help|info|news|blog|shop|store|mail|email|noreply|no-reply|sample|demo)$"
  + "|\\.(?:com|net|org|io|co|edu|gov|uk|de|fr|ai|app|dev|me|info|biz|us|ca|au|in|jp|cn|ru|br|es|it|nl|se|ch|xyz|tv|ly|to|cc|eu|be|at|pl|cz|dk|fi|no|nz|za|mx|ar|cl|kr|tw|hk|sg|id|ph|vn|th|my|tr|il|ie|pt|gr|hu|ro|ua|sk|si|hr|bg|lt|lv|ee|is|lu)$",
);

/**
 * A street with no number and an ordinary street word, after the word that
 * puts somebody there: "at Skye Crossing", "on Kutch Divide", "at Delpha
 * Streets". findStructured takes it only when the name in front reads as a
 * person's. Not after "in" ("in Silicon Valley" is a region), and not with
 * the words that name famous places more often than streets — "on Pearl
 * Harbor", "at Capitol Hill", "on Mindanao Island", "near Hyde Park", "on
 * European Union" all came back from real prompts and the TAB judgments.
 */
const STREET_WORDS_UNFAMOUS = [
  "Crossing", "Crossroad", "Divide", "Divides", "Trace", "Traces", "Spur", "Spurs", "Junction", "Junctions",
  "Ford", "Fords", "Pines", "Streets", "Ways", "Way", "Haven", "Havens", "Cove", "Coves", "Dale", "Glen",
  "Glens", "Meadows", "Meadow", "Ridge", "Ridges", "Knoll", "Knolls", "Hollow", "Shoal", "Shoals", "Rapids",
  "Bend", "Burg", "Burgs", "Corners", "Crest", "Estates", "Extension", "Extensions", "Flats", "Forks",
  "Gateway", "Gateways", "Heights", "Inlet", "Landing", "Landings", "Locks", "Loop", "Manor", "Manors",
  "Neck", "Necks", "Orchard", "Orchards", "Oval", "Ovals", "Passage", "Passages", "Path", "Paths", "Pike",
  "Pikes", "Plains", "Prairie", "Prairies", "Radial", "Ramp", "Ramps", "Ranch", "Ranches", "Rest", "Row",
  "Rows", "Run", "Runs", "Shores", "Stream", "Summit", "Summits", "Trail", "Trails", "Tunnel", "Tunnels",
  "Unions", "Views", "Villages", "Ville", "Vistas", "Walks", "Wells", "Wynd", "Brooks", "Forges", "Groves",
  "Lights", "Loaf", "Mountains", "Drives", "Roads", "Avenues", "Lanes", "Curve",
].join("|");
export const WEAK_STREET_CUED_PATTERN = new RegExp(
  String.raw`(?<=(?:\b(?:at|on|near|visit|located\s+at|residing\s+at|address\s+is|lives?\s+on)|${STREET_CUES_INTL})\s)((?:\p{Lu}[\p{L}'’-]+[ \t]+){1,2}(?:${STREET_WORDS_UNFAMOUS}))\b(?![ \t]+\p{Lu})(?!\s+(?!${AFTER_A_STREET}\b)[a-z])`,
  "gu",
);

/**
 * A phone number after the small word French, German and Italian put in
 * front of one: "contacter Godfrey Becker au +61.38.625.4974", "composer le
 * 07.70.55.77.98", "unter (33) 6983-6021", "chiamaci al (23)-5221.8913",
 * "Chiama il 7185-483-5402", "votre nouveau 06.36-58-75 31". The words are
 * everywhere, so findStructured asks more of the number than
 * PHONE_CUED_INTL_PATTERN does: eight digits or more, written the way a
 * phone is (a plus, a bracket, or two separators), and not a date.
 */
/**
 * A national number with its trunk zero, written the ways the other phone
 * patterns pass over: a bracketed area code with a hyphen after it,
 * "(02)-6378-6141"; a four-digit one, "(0312) 456 7890"; two hyphens,
 * "09-345-2347". Gretel's PII test set (2026-10-05) wrote a third of its
 * missed phones like this. The shape alone is a date or a part number as
 * often as a phone, so findStructured asks for a phone word just before it,
 * or another number and "or".
 */
/**
 * A phone written with mixed separators, or a plus and dots: "+90.909-448.6913",
 * "0151 07987.2078", "06-5634 8945", "(80)-0433.6288", "+31.40825.6044". The
 * multilingual set writes a quarter of its phones so, and every one was
 * missed (2026-10-31). Nine to fourteen digits ending in a group of four;
 * findStructured asks for a plus, or two different separators, which a date,
 * a version or a part number does not mix.
 *
 * Chinese, Japanese and Thai put no space between a number and the words
 * around it, and Korean writes its particle onto the number: "通过
 * +86.18569.1944收集", "+82.428.773-5563로" (moreLanguages practice half,
 * 2026-11-02). Their letters may touch it; any other script's may not.
 */
const NO_SPACE_SCRIPT = String.raw`\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Hangul}\p{Script=Thai}`;
export const PHONE_MIXED_PATTERN = new RegExp(
  String.raw`(?<![\p{N}.,\/:#=_+-]|(?![${NO_SPACE_SCRIPT}])\p{L})(?:\+\d{1,4}|\(\d{1,4}\)|\d{1,5})(?:[ .\-]{1,2}\(?\d{1,5}\)?){1,4}[ .\-]\d{4}(?!(?![${NO_SPACE_SCRIPT}])\p{L}|\p{N}|[.,:\-\/]\d)`,
  "gu",
);

/**
 * National phones that open with the trunk 0, in the groups their country
 * writes, which the shape above misses because they do not end in four or
 * keep to one separator: a French number in pairs with any mix of
 * separators, "07-33.49 92-89"; Germany's area code and number,
 * "0921-99588109"; Australia's, "02-4197-3268", "07.3739.8794"; and a plus
 * with one dot, "+49.189794500" (open-pii-masking practice half,
 * 2026-11-02). Every match in 109,457 real and test texts was a phone.
 */
export const PHONE_ZERO_GROUPS_PATTERN =
  /(?<![\p{L}\p{N}.,\/:#=_+\-]|\d[ .\-])(?:0[1-9](?:[ .\-]\d{2}){4}|0\d{3}-\d{8}|0\d([.\-])\d{4}\1\d{4}|\+\d{1,3}\.\d{8,10})(?![\p{L}\p{N}]|[ .,:\-\/]\d)/gu;

export const PHONE_TRUNK_PATTERN =
  /(?<![\w+.\/-])(\(0\d{1,4}\)(?:[-. ]|\)?-)?\d{2,4}(?:[-. ]\d{2,4}){1,2}|0\d{1,4}[-. ]\d{2,4}(?:[-. ]\d{2,4}){1,2})(?![\w\/-]|[.,]\d)/g;

export const PHONE_SMALL_CUE_PATTERN =
  /(?<![\p{L}])(?:au(?:\s+num[ée]ro(?:\s+suivant)?)?|le|unter|al(?:\s+numero)?|il|numero|num[ée]ro|nummer|nouveau|neue[nr]?|nuovo|attuale|actuel)[ \t]+(\+?\(?\d[\d ()./-]{6,18}\d)(?![\d.,]?\d)/giud;

/**
 * An account a payment goes to or comes from, with no word for it: "Account
 * payments should be sent to 40073954", "credited to 49720667", "paid from
 * our 20685264", "Transfer payment at 72176838", "make payment through
 * 67212066", "Bill fees to 24024758", "donate to 40643115". The verb and its
 * preposition are the label; six to twelve digits, standing alone.
 */
export const ACCOUNT_PAYMENT_PATTERN =
  /(?<![\p{L}])(?:sen[dt]|transfer(?:red)?|credit(?:ed)?|debit(?:ed)?|paid|pay|payments?|deposit(?:ed)?|bill(?:ed)?|charg(?:e|ed)|donat(?:e|ed)|wire[ds]?|remit(?:ted)?|refund(?:ed)?|withdraw(?:n)?|fees?|funds?|vir(?:er|ement|ez|é)|vers(?:er|ement|é|ez)|pay(?:er|é|ez)|crédit(?:er|é)|überw(?:eisen|eisung|iesen)|einzahl(?:en|ung)|gutgeschrieben|bezahl(?:en|t)|zahl(?:en|ung)|bonific(?:o|are|ate)|vers(?:are|ato|ate)|accredit(?:ato|are)|pagat[oa]|pagamento|pagare)(?![\p{L}])(?:[ \t]+(?!(?:to|from|into|through|at|via|between|sur|à|au|auf|an|su|sul|al|a)(?![\p{L}]))(?:[\p{L}']+|\p{Sc}?\p{L}{0,4}\d[\d.,]*\p{L}{0,8})){0,3}[ \t]+(?:to|from|into|through|at|via|between|sur|à|au|auf|an|su|sul|al|a)[ \t]+(?:(?:our|your|the|my|his|her|their|account|acct\.?|acc\.?|le|la|votre|notre|compte|das|dein|Ihr|Konto|il|tuo|vostro|conto)[ \t]+){0,2}(?<![\d.,])(\d{6,12})(?![\d.,]?\d|[A-Za-z@])/giud;

/**
 * A customer's own order code, after the word for an order: "min ordre
 * DK-30917", "order WX-559201", "tilausnumero FI-80442", "jag har
 * ordernummer SE-778120", "pedido PED-7730184", "ஆர்டர்எண்ORD-TN-558102".
 * Letters, a hyphen or a slash, then digits, as all twelve were ("AB12345" is
 * a promo code as often): a plain number ("Pedido 55102")
 * names a purchase, and an invoice's ("factura 2026-77", "FACTURE N°
 * F-2026-087") a company's paperwork; both stay visible. findStructured
 * asks the message to be the customer's own as well (ORDER_CODE_PERSONAL),
 * so "your order ORD-559201 has shipped" stays as written.
 */
export const ORDER_CODE_PATTERN =
  /(?<![\p{L}])(?:order(?:\s+(?:number|no\.?|id|ref(?:erence)?))?|ordre(?:nummer|nr\.?)?|ordernummer|ordernr\.?|bestellnummer|bestellung(?:\s+nr\.?)?|tilaus(?:numero)?|beställning(?:snummer)?|pedido(?:\s+n[º°o.]*)?|n[úu]mero\s+de\s+pedido|commande(?:\s+n[°o.]*)?|num[ée]ro\s+de\s+commande|ordine(?:\s+n\.?)?|numero\s+(?:d['’]\s*)?ordine|zam[óo]wienie(?:\s+nr\.?)?|objedn[áa]vk[ay](?:\s+(?:č\.|číslo))?|заказ(?:а)?(?:\s+№)?|замовлення(?:\s+№)?|sipari[şs](?:\s+no)?|pesanan|ஆர்டர்(?:\s*எண்)?|ఆర్డర్(?:\s*నం)?|ऑर्डर(?:\s*नंबर)?|注文番号|订单号|주문번호)(?:\s*(?:is|es|er|är|on|est|ist|è|:|#|№))?\s*[:#]?\s*((?=[\p{Lu}\d\/-]*\d)\p{Lu}{1,5}(?:[-\/]\p{Lu}{1,5})*[-\/]\d{3,}(?:[-\/]\d{2,})*)(?![\p{L}\d])/giud;

/** The customer writing about their own order: "my", "I am", "my name is", in the
 *  messages' languages. */
export const ORDER_CODE_PERSONAL =
  /(?<![\p{L}])(?:my|i'?m|i\s+am|i\s+have|i\s+ordered|min|mit|mitt|mine|jeg|jag|olen|minun|tilasin|mi|mis|me\s+llamo|soy|compr[ée]|mon|ma|je|mein|meine|ich|mio|mia|sono|mój|moje|moja|jestem|můj|moje|jsem|мой|моя|мій|моя|я|benim|saya|என்|నా|मेरा|मेरी|私の|我的|제)(?![\p{L}])/iu;

/**
 * Eight digits standing alone in a sentence, with no word for them: "Use
 * 68557984 to log in", "the change of 32173095", "Your 70637559 holds the
 * payment". Eight bare digits in a message to or about a person is an account
 * or a member number far more often than anything else, and every pattern
 * with a label has already had its turn. Exactly eight: seven is a phone or a
 * count, nine is a national ID's shape and has its own rules. Not inside a
 * longer token, a price, a decimal, a path or a range.
 */
export const ACCOUNT_BARE_PATTERN = /(?<![\p{L}\p{N}#№$€£¥₹.,:\/+\-_@=&?%|])(?<!https?:\/\/\S*)(\d{8})(?![\p{L}\p{N}%$€£¥₹\/\-_@|]|[.,:]\d)/gud;

/**
 * The words that make an eight-digit number a reference, which stays visible:
 * an order, an invoice, a ticket, a booking, a case, a shipment, a part. Read
 * from the forty characters before the number.
 */
export const BARE_EIGHT_NOT_AN_ACCOUNT =
  /(?:\b(?:orders?|invoices?|inv|po|purchase\s+order|tickets?|case|cases|ref|refs|reference|booking|reservation|confirmation|tracking|shipment|parcel|consignment|delivery|items?|sku|part|model|serial|batch|lot|job|build|version|issue|bug|pr|commit|page|line|isbn|issn|flight|train|room|zip|postcode|otp|code|pin|ticket|quote|quotation|estimate|receipt|transaction\s+id|txn|rma|dossier|commande|facture|bestellung|rechnung|auftrag|pedido|factura|ordine|fattura|zamówienie|faktura|pubmed|pmid|pmc|doi|arxiv|patent|chapter|section|sec|port|suite|route|highway|extension|ext|step|level|stage|episode|season|volume|vol|figure|fig|table|exhibit|article|paragraph|clause|platform|gate|seat|bus)\b\W{0,4}(?:(?:no|nr|num|number|id|#)\b\W{0,3})?|#\s*)$/i;

/** A count of something, not an account: "12000000 users", "20000000 rows". */
export const BARE_EIGHT_COUNTS =
  /^\s*(?:users?|requests?|points?|rows?|records?|items?|customers?|members?|transactions?|calls?|messages?|visits?|views?|followers?|subscribers?|units?|tokens?|bytes?|kb|mb|gb|ms|seconds?|minutes?|hours?|days?|years?|people|copies|downloads?|hits?|times?|km|kg|g|grams?|kilograms?|mg|ml|millilit(?:re|er)s?|lit(?:re|er)s?|met(?:re|er)s?|miles?|degrees?|calories|steps?|tons?|tonnes?|barrels?|shares?|dollars?|euros?|pounds?|usd|eur|gbp|jpy|yen)\b/i;

/**
 * A flat number on its own: "update your shipping address … Apt. 326", "I
 * live at this Apt. 844", "Dear Apt. 387 resident". A flat is part of a
 * home's address however little of the rest is written; a suite is an
 * office's, and "Suite 300, second floor." stays a sentence (redaction.eval).
 * Capitalised, so "apt to" and "an apt 3-word summary" are words.
 */
/**
 * A Brazilian form's address under its short label, "END.:" for endereço:
 * "END.: RUA DAS PALMEIRAS, 1450 AP 32 CEP: 04567-120" (realistic5,
 * 2026-10-31). With the dot and the colon only: a field called "end" is a
 * time far more often. Up to the next label on the line.
 */
export const END_LABEL_PATTERN =
  /(?<![\p{L}])(?:END|End)\.[ \t]*:[ \t]*([^\n]{4,80}?)(?=[ \t]+(?:CEP|Cep|TEL|Tel|FONE|Fone|CEL|Cel|BAIRRO|Bairro|CIDADE|Cidade|UF|E-?MAIL|E-?mail)\b|[ \t]{2,}|[ \t]*[|;]|\n|$)/gud;

/**
 * Argentina's postcode, the CPA: a province letter, four digits and three
 * letters, "C1416DKE"; or the letter and four digits alone after a street
 * number and before the city, "Av. San Martín 1820, C1416 CABA" (realistic5,
 * 2026-10-31). The province letters skip I and O.
 */
export const AR_CPA_PATTERN =
  /(?<![\p{L}\d])([A-HJ-NP-Z]\d{4}[A-Z]{3})(?![\p{L}\d])|(?<=\d{1,5},?[ \t]+)([A-HJ-NP-Z]\d{4})(?=[ \t]+(?:CABA|Capital|Buenos|\p{Lu}\p{Ll}{2,}))/gud;

/**
 * A building's number under its own words: "building number 905", "the
 * building number is 511", "Building no. 920", "her house number is
 * 58447". "Building 42" alone is a block on a campus, and stays. And a
 * number of three digits or more with "on" and a street after it, the way
 * a meeting place is given: "Volunteer meet-up at 68266 on Bogisich Way",
 * "the abandoned building 57993 on Marge Road" (ai4privacy practice
 * half, 2026-10-31). A room or a classroom is not here: it is a place in a
 * building, nobody's address.
 */
export const BUILDING_CUED_PATTERN =
  /\b(?:building|house|bldg\.?)\s*(?:number|no\.|num\.?|#)(?:\s+is)?\s*[:#]?\s*(\d{1,6}[A-Za-z]?)(?![\p{L}\d]|[.,]\d)/giud;
export const NUMBER_ON_STREET_PATTERN = new RegExp(
  String.raw`(?<![\p{L}\d.,$€£#-])(\d{3,6})[ \t]+on[ \t]+((?:[A-Z][\p{L}'’-]*[ \t]+){1,3}(?:${STREET_WORDS_STRONG}|${STREET_WORDS_WEAK}))(?![\p{L}\d])`,
  "gud",
);

export const APT_ALONE_PATTERN =/(?<![\p{L}])((?:Apt\.?|Apartment|Appt\.?|Appartement|Appartamento|Wohnung)[ \t]*(?:No\.?|Nr\.?|n[°º])?[ \t]*#?[ \t]*\d{1,5}[A-Za-z]?)(?![\p{L}\d])/gu;

/**
 * A Dutch postcode with no street before it: "mijn 1358 is 8166 KZ",
 * "verzonden naar Dennenlaan 35A in 3646 AJ". Four digits and two capitals
 * after a small Dutch (or English) word. The letter pairs that are something
 * else — "2024 AD", "1500 BC", "2000 GB", "8000 MB", "1080 HD", "3000 KM" —
 * are refused here, and SA, SD and SS are never issued.
 */
export const NL_POSTCODE_ALONE_PATTERN =
  /(?<=(?<![\p{L}])(?:in|is|uw|mijn|onze|naar|te|postcode|de|het|van)[ \t]+)([1-9]\d{3}[ \t]?(?!(?:AD|BC|AM|PM|KB|MB|GB|TB|PB|HD|SD|SS|SA|CE|KM|KG|MG|ML|HZ|KW|MW|GW|PS|HP|EU|US|UK|OK|TV|PC|ID|CM|MM|LB|OZ|FT|IN|XL|DJ|MP|RS|EX|LP|EP|CD|BV|NV)(?![A-Z]))[A-Z]{2})(?![\p{L}\d])/gu;

/**
 * An identifier after the word that makes it somebody's, with no label for
 * what it is: "kannst du bitte deine AT8126685 senden", "votre I2128346",
 * "su K4796345J", "il tuo W6292668", "uw KB019215A46", "मेरा ZY8055478",
 * "please provide your 998605650". Letters and digits together, or eight
 * digits and more; findStructured refuses the shapes that are things.
 */
export const ID_POSSESSIVE_PATTERN = new RegExp(
  // The word in either case: a sentence starts with it ("Uw 629102323 is
  // nodig", multilingual practice half, 2026-11-02).
  String.raw`(?<![\p{L}])(?:${anyCase(String.raw`your|my|his|her|their|our|votre|vos|mon|ma|mes|son|sa|ses|leur|notre|ton|ta|deine?[nmrs]?|ihre?[nmrs]?|meine?[nmrs]?|seine?[nmrs]?|unsere?[nmrs]?|euer|eure[nmrs]?|su|sus|mi|mis|tu|tus|nuestr[oa]s?|il\s+(?:tuo|mio|suo|vostro|nostro)|la\s+(?:tua|mia|sua|vostra|nostra)|i\s+(?:tuoi|miei|suoi)|uw|mijn|je|zijn|haar|onze|मेरा|मेरी|आपका|आपकी|उनका|उनकी|మీ|నా`)}` +
  String.raw`)[ \t]+(?:\(\s*)?((?=[A-Z0-9]*\d)(?:[A-Z0-9]{7,14}|\d{8,12}))(?![\p{L}\d@.-]|\.\d)`,
  "gud",
);

/**
 * An identifier in capitals and digits standing alone, where the two kinds
 * of character take turns: "C2TZXGY7LR", "4TNU3U6103", "XLJTPKA0XJ",
 * "B7F5SX6518". A product code keeps its letters together and its digits
 * together ("RTX3080", "ABC12345"); a hash is hex; neither alternates.
 *
 * Japanese, Chinese, Korean and Arabic write a particle or a label straight
 * onto it — "関連資料はB6Q0P2A1WTで", "请准备好您的UPPE2INQ8T和" — so only a
 * letter of an alphabet with spaces (Latin, Cyrillic, Greek) welds it to a
 * word (moreLanguages practice half, 2026-10-31).
 */
export const ID_UPPER_TOKEN_PATTERN = /(?<![\p{Script=Latin}\p{Script=Cyrillic}\p{Script=Greek}\d@./:#=_-])([A-Z0-9]{8,12})(?![\p{Script=Latin}\p{Script=Cyrillic}\p{Script=Greek}\d@/=_-]|\.\w)/gud;

/**
 * The shapes a national ID takes and a product code does not: letters,
 * five digits or more, and a closing letter ("D3727035Z", "P6843932S",
 * "VQ79773JG", "LOC542301A", a NINO's "AB123456C"); one letter and twelve
 * digits or more ("M1905661848848"); eight digits and a check letter
 * ("92531324S", a DNI whose letter is wrong). A product keeps its letters
 * together and its digits together and does not close on a letter after
 * five digits; findStructured refuses the prefixes that are things.
 * Multilingual practice half, 2026-10-31.
 */
export const ID_SANDWICH_PATTERN = /(?<![\p{L}\d@./:#=_-])([A-Z]{1,3}\d{5,10}[A-Z]{1,2}|[A-Z]\d{12,14}|\d{7,8}[A-Z])(?![\p{L}\d@\/=_-]|\.\w)/gud;

/**
 * China's resident identity number, which is also the tax number: six
 * digits of region, the birth date as YYYYMMDD, three of sequence and a
 * check digit or X — "421119198810064538", "24668819890718695X". The date in
 * its place is what tells it from any other eighteen digits; the region and
 * the check are not asked, since a copied or mistyped one fails them and is
 * still somebody's (moreLanguages practice half, 2026-10-31: 26 of 27
 * Chinese tax numbers missed).
 */
export const CN_RESIDENT_ID_PATTERN = /(?<![\p{Script=Latin}\p{Script=Cyrillic}\p{Script=Greek}\p{N}_.\/-])(\d{6}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx])(?![\p{Script=Latin}\p{Script=Cyrillic}\p{Script=Greek}\p{N}_\/-]|[.,]\d)/gud;

/*
 * Two branches of ADDRESS_PATTERN that only another language can need, kept
 * apart so findStructured runs them only when the message has that language
 * in it. Inside the one alternation their lookbehinds were tried at every
 * position of every message, English included, and made it a fifth slower.
 */

/** "पता: Dhaulha Road 670", "మా Akurli Road 833": a road in Latin letters
 *  inside Hindi, Telugu or any other script, with no English cue in front.
 *  The switch of script is the evidence the preposition would have been. */
export const ADDRESS_NON_LATIN_PATTERN = new RegExp(
  String.raw`(?<=${NON_LATIN_BEFORE})(?:${NAME_WORD}){1,4}(?:${STREET_WORDS_STRONG}),?\s+\d{1,5}\b`,
  "gu",
);
/**
 * A house and its street in the scripts of South Asia, Arabic and Thai, the
 * way their forms write them: the word for a house or flat and its number,
 * then the lane, block and area after commas ("मकान नं. 27, गली नं. 4,
 * राजेंद्र नगर", "বাসা ১৮, রোড ৭, ধানমন্ডি", "مکان نمبر 45، گلی نمبر 7", "ఇం.నం.
 * 8-3-221, శ్రీనగర్ కాలనీ"); or a number and a street named by its own word
 * ("12/3 सिविल लाइंस", "২৩/১ রাসবিহারী অ্যাভিনিউ", "12, பாரதி நகர் 3வது
 * தெரு", "99/12 ซอยลาดพร้าว 71 ถนนลาดพร้าว", "شارع الوحدة، بناية 12، شقة
 * 305"). realistic5 missed nearly every one (2026-10-25). Digits in either
 * form, Latin or the script's own; parts after a comma are one to four words.
 */
function houseFirst(letters: string, house: string, parts: number): string {
  // A full stop only inside a word or after a short one: "वृ.उ.सि.", "नं.",
  // never one that ends a sentence.
  const word = String.raw`(?:[${letters}]+(?:\.[${letters}]+)+\.?|[${letters}]{1,3}\.|[${letters}]+)`;
  // A letter may follow, with its vowel sign: "৫বি", "3B". Not a sum's first
  // group: "ভাড়া ২২,০০০".
  const num = String.raw`(?:[A-Za-z${letters}]{1,2}-)?\p{Nd}{1,5}(?:[/-]\p{Nd}{1,4})*[A-Za-z${letters}]{0,2}(?![,.]?\p{Nd})`;
  const part = String.raw`(?:${word}(?:[ \t]+(?:${word}|${num})){0,3})`;
  return String.raw`(?<![${letters}\p{Nd}])(?:${house})[ \t]*[:.-]?[ \t]*${num}(?:[ \t]*[,،][ \t]*${part}){1,${parts}}`;
}
function numberFirst(letters: string, street: string): string {
  const word = String.raw`(?:[${letters}]+(?:\.[${letters}]+)+\.?|[${letters}]{1,3}\.|[${letters}]+)`;
  // A block letter may lead the number: "बी-14".
  return String.raw`(?<![${letters}\p{Nd}/-])(?:[${letters}]{1,3}-)?\p{Nd}{1,4}(?:/\p{Nd}{1,4})?,?[ \t]+(?:${word}[ \t]+){0,3}?(?:${street})(?![${letters}])(?:[ \t]+\p{Nd}{1,3}(?:[${letters}]+)?)?(?:[ \t]*,[ \t]*${word}(?:[ \t]+${word}){0,2})?`;
}
const DEVANAGARI = String.raw`ऀ-ॣ॰-ॿ`;
const BENGALI = String.raw`ঀ-৥ৰ-৿`;
const TAMIL = String.raw`஀-௥௰-௿`;
const TELUGU = String.raw`ఀ-౥౰-౿`;
const ARABIC = String.raw`؀-ٟٮ-ۯۺ-ۿ`;
export const SOUTH_ASIAN_ADDRESS_PATTERN = new RegExp([
  houseFirst(DEVANAGARI, String.raw`मकान(?:[ \t]*(?:नं\.?|नंबर|संख्या))?|फ्लैट(?:[ \t]*(?:नं\.?|नंबर))?|प्लॉट(?:[ \t]*(?:नं\.?|नंबर))?|हाउस[ \t]*नं\.?|म\.[ \t]?नं\.?`, 3),
  numberFirst(DEVANAGARI, String.raw`नगर|पार्क|लाइंस|कॉलोनी|मार्ग|रोड|विहार|एन्क्लेव|पुरम|चौक|बाग`),
  houseFirst(BENGALI, String.raw`বাসা|বাড়ি|ফ্ল্যাট|হাউস|প্লট|বাড়ি[ \t]*নং`, 3),
  numberFirst(BENGALI, String.raw`অ্যাভিনিউ|রোড|সড়ক|লেন|সরণি|নগর`),
  houseFirst(TELUGU, String.raw`ఇం\.?[ \t]?నం\.?|డో\.?[ \t]?నం\.?|ఇంటి[ \t]+నంబర్|ఫ్లాట్[ \t]+నం\.?`, 3),
  numberFirst(TAMIL, String.raw`நகர்|தெரு|சாலை|வீதி|காலனி|புரம்|பேட்டை`),
  houseFirst(ARABIC, String.raw`مکان(?:[ \t]+نمبر)?|فلیٹ(?:[ \t]+نمبر)?|پلاٹ(?:[ \t]+نمبر)?|ہاؤس(?:[ \t]+نمبر)?`, 3),
  // Arabic: the street first, then its building and flat.
  String.raw`(?<![${ARABIC}])شارع(?:[ \t]+[${ARABIC}]+){1,3}(?:[ \t]*[,،][ \t]*(?:بناية|عمارة|مبنى|شقة|طابق|الدور)[ \t]*\p{Nd}{1,5}){1,3}`,
  String.raw`(?<![${ARABIC}\p{Nd}])\p{Nd}{1,4}[ \t]+شارع(?:[ \t]+[${ARABIC}]+){1,2}(?:[ \t]*[,،][ \t]*[${ARABIC}]+(?:[ \t]+[${ARABIC}]+)?)?`,
  // Thai: the house number, then a soi, road, sub-district and district.
  String.raw`(?<![\p{Nd}/])\p{Nd}{1,4}(?:/\p{Nd}{1,4})?(?:[ \t]*หมู่[ \t]*\p{Nd}{1,3})?(?:[ \t]*(?:ซอย|ซ\.|ถนน|ถ\.|แขวง|ตำบล|ต\.|อำเภอ|อ\.|เขต|หมู่บ้าน|คอนโด)[ก-ฮะ-ฺเ-๎]+(?:[ \t]*\p{Nd}{1,3})?){1,5}`,
].join("|"), "gu");
/** Words of a measure or a date between the road and its number: "شارع
 *  عرض 20" is a street twenty metres wide, "بتاريخ 10" a date. */
export const ARABIC_ROAD_NOT = /(?:^|[ \t])(?:عرض\p{L}*|بعرض|طول|بطول|تاريخ|بتاريخ|مساحة|بمساحة|سرعة|متر|كم|كيلو)(?=[ \t]|$)/u;
/** An Arabic street or road, its name, its number, then the town and
 *  postcode: "طريق العليا 794، الرياض 01479" (leak hunt, 2026-11-14). Scanned
 *  before the label rules, which took the street's name alone and left its
 *  number, town and postcode. */
const AR_LETTERS = String.raw`\u0621-\u064A\u0671-\u06D3`;
export const ARABIC_ROAD_PATTERN = new RegExp(String.raw`(?<![${AR_LETTERS}])(?<!عن[ \t])(?:شارع|طريق)(?:[ \t]+[${AR_LETTERS}]+){1,3}[ \t]+\p{Nd}{1,5}(?![\p{Nd}\/.\-])(?:[ \t]*[,،][ \t]*[${AR_LETTERS}]+(?:[ \t]+\p{Nd}{5})?)?`, "gu");

/** Run SOUTH_ASIAN_ADDRESS_PATTERN at all: a letter of one of its scripts. */
export const HAS_SOUTH_ASIAN_OR_ARABIC = /[؀-ۿऀ-౿฀-๿]/;

/** Run ADDRESS_NON_LATIN_PATTERN at all: a letter of one of those scripts. */
export const HAS_NON_LATIN = /[Ͱ-ϿЀ-ӿ֐-ۿऀ-෿฀-๿぀-ヿ㐀-鿿가-힯]/;

/** "à Fritz Street", "situé au School Close", "in der Meadow Lane": a street
 *  with no number after the French, German or Italian word that puts
 *  somebody there. The English cues are ADDRESS_PATTERN's. */
export const ADDRESS_INTL_CUED_PATTERN = new RegExp(
  String.raw`(?<=${STREET_CUES_INTL}\s(?:(?:the|our|your|their|his|her|my|its)\s+)?)(?:${NAME_WORD}){1,4}(?:${STREET_WORDS_STRONG_NUMBERLESS})\b(?!\s+(?!${AFTER_A_STREET}\b)[a-z])(?!(?<=St)\.[ \t]*\p{Lu})`,
  "gu",
);
/**
 * A street and its number in the other languages' own words, with the word
 * for a street before the name ("via dei Mille 38", "Calea Victoriei 140",
 * "вул. Сумська, 45, кв. 18", "пр. Мира, д. 101", "c/ Almirante 23, 3ºB",
 * "Rua Voluntários da Pátria, 318, casa 2") or after it, alone or as the end
 * of the name ("Elgeseter gate 40", "Savska cesta 101", "Óváros tér 3.",
 * "Tallstigen 7", "Industriestr. 44", "Moda Cad. No:45"); and Colombia's
 * "Carrera 15 # 93-47". realistic5 missed nearly every one (2026-10-24).
 * A flat, floor or door may follow, up to two of them.
 */
const WORLD_STREET_BEFORE = String.raw`(?:via|viale|vicolo|piazza|piazzale|corso|largo|rue|avenue|av\.|boulevard|bd\.|place|quai|chemin|impasse|allée|calle|c\/|carrer|avinguda|avda\.|avenida|paseo|plaza|rua|travessa|praça|estrada|alameda|calea|strada|str\.|bulevardul|bdul\.|aleea|șoseaua|ul\.|ulica|ulice|aleja|al\.|вул\.|вулиця|ул\.|улица|пр\.|просп\.|проспект|пр-т|пер\.|переулок|провулок|бульв\.|бульвар|наб\.|шосе|шоссе|đường|phố|jalan|jl\.|jln\.|οδός|λεωφ\.|λεωφόρος)`;
const WORLD_STREET_AFTER = String.raw`(?:gatan|gata|gate|vägen|väg|stigen|gränd|torget|backen|veien|vei|vej|gade|stræde|allé|straße|strasse|str\.|weg|laan|straat|gracht|plein|katu|tie|kuja|utca|út|körút|tér|cesta|bulvarı|caddesi|cad\.|sokak|sok\.)`;
// Run into the name, less the endings ordinary words have: "Partie",
// "Sortie", "Citygate", "Allé" in a heading.
const WORLD_STREET_GLUED = String.raw`(?:gatan|vägen|stigen|gränd|torget|backen|veien|vej|gade|stræde|straße|strasse|str\.|weg|straat|gracht|katu|kuja|utca|körút)`;
// Or a letter and a number, as Goiânia names its streets: "Av. T-63", "Rua C-140".
const WORLD_STREET_NAME = String.raw`(?:\p{Lu}[\p{L}\p{M}'’.-]*|\p{Lu}{1,2}-\d{1,4}(?![\p{L}\p{N}]))`;
// In capitals too, as a form writes them: "RUA DAS PALMEIRAS, 1450 AP 32".
const WORLD_STREET_PARTICLE = String.raw`(?:de|del|della|dei|degli|delle|di|da|do|dos|das|du|des|la|le|les|l['’]|d['’]|dels|y|e|i|DE|DEL|DA|DO|DOS|DAS|LA|LOS|LAS)`;
const WORLD_STREET_NUMBER = String.raw`(?:n[º°o]\.?[ \t]*|No:?[ \t]*|nr\.?[ \t]*|д\.[ \t]*)?\d{1,4}[A-Za-z]?(?:[/-]\d{1,4}[A-Za-z]?)?\.?`;
const WORLD_STREET_UNIT = String.raw`(?:,?[ \t]+(?:(?:apto\.?|apt\.?|ap\.?|APTO\.?|APT\.?|AP\.?|piso|puerta|casa|CASA|kv\.|кв\.|квартира|корп\.|bl\.|sc\.|et\.|lgh|int\.|interno|scala)[ \t]*\d{1,4}[A-Za-z]?|\d{1,2}[ºª°][ \t]?[A-Za-z]{0,3}\.?|\d{1,2}\.[ºª][ \t]?(?:Esq|Dto|Dt|Dir)\.?|\d{1,2}[a-z]{1,2}[ \t]\d{1,2}[a-z]{1,2})){0,2}`;
// Run into the word before it where the spaces were lost, as a preposition
// is: "residente naAv. T-63", "residente emAv. da República, 88" (realistic5,
// 2026-10-27).
const WORLD_STREET_GLUED_ON = String.raw`(?<=(?<![\p{L}\p{N}])(?:na|no|em|en|al|del)(?=\p{Lu}))`;
export const WORLD_STREET_PATTERN = new RegExp(
  String.raw`(?:(?<![\p{L}\p{N}])|${WORLD_STREET_GLUED_ON})(?:` +
    // A word that ends in a full stop ends the name: "Rue de Miromesnil. Ab 1879".
    String.raw`${anyCase(WORLD_STREET_BEFORE)}[ \t]+(?:${WORLD_STREET_PARTICLE}[ \t]+)?${WORLD_STREET_NAME}(?:(?<!\.)[ \t]+(?:${WORLD_STREET_PARTICLE}[ \t]+)?${WORLD_STREET_NAME}){0,3}` +
    String.raw`|(?:${WORLD_STREET_NAME}(?<!\.)[ \t]+){0,2}(?:\p{Lu}[\p{Ll}\p{M}]{2,}${WORLD_STREET_GLUED}|\p{Lu}[\p{Ll}\p{M}]+[ \t]+${anyCase(WORLD_STREET_AFTER)})` +
  String.raw`),?[ \t]+${WORLD_STREET_NUMBER}${WORLD_STREET_UNIT}(?![\p{L}\p{N}])` +
  // French writes the number first: "5 place du Marché", "12 bis rue de la Paix".
  String.raw`|(?<![\p{L}\p{N}])\d{1,4}(?:[ \t]?(?:bis|ter))?,?[ \t]+(?:rue|avenue|av\.|boulevard|bd\.|place|quai|chemin|impasse|allée|route)[ \t]+(?:${WORLD_STREET_PARTICLE}[ \t]+)?${WORLD_STREET_NAME}(?:[ \t]+(?:${WORLD_STREET_PARTICLE}[ \t]+)?${WORLD_STREET_NAME}){0,3}(?![\p{L}\p{N}])` +
  String.raw`|(?<![\p{L}\p{N}])(?:[Cc]arrera|[Cc]alle|[Cc]ra\.|[Cc]l\.|[Aa]venida|[Aa]v\.|[Tt]ransversal|[Dd]iagonal)[ \t]+\d{1,3}[A-Z]?[ \t]*(?:#|[Nn]o\.?|N°)[ \t]*\d{1,3}[A-Z]?-\d{1,3}${WORLD_STREET_UNIT}(?![\p{L}\p{N}])`,
  "gu",
);

/** Run ADDRESS_INTL_CUED_PATTERN at all: one of its words in the message. */
export const HAS_STREET_CUE_INTL = /(?<![\p{L}])(?:à|au|aux|sur|rue|situé|dans|der|bei|lautet|Straße|befindet|presso|via|situat[oa]|al|alla|indirizzo)\s/u;

/**
 * The address of a machine that tried to log in, as sshd and PAM write it:
 * "Failed password for root from 173.234.31.186 port 38926 ssh2", "rhost=
 * 218.65.30.43 user=root", "Received disconnect from 112.95.230.3: 11: Bye",
 * "Connection closed by 5.188.10.180 [preauth]", "getaddrinfo for … [218.65.
 * 30.43] failed". A public address is otherwise taken only under a label
 * (IP_LABELLED_PATTERN); in an authentication log the line is the label, and
 * an address there is somebody's connection. Loghub's OpenSSH set had 1,500.
 */
export const AUTH_LOG_IP_PATTERN =
  /(?:\brhost=|\b(?:from|by)[ \t]+|\[)((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})(?=[ \t]+port[ \t]+\d|:[ \t]*\d+:|[ \t]+\[preauth\]|[ \t]+user=|\][ \t]+failed|[ \t]*$)/gmd;

/**
 * A bank's SWIFT/BIC code with no label: "Bank details: BR07…, BDWGNLAA",
 * "make the payment of Naira to WULNLKER", "include KRJUPTS2XXX". Four
 * letters of bank, two of country, two of place, and three of branch or
 * none. findStructured takes it when the country is real and the message is
 * about money, or when it ends in "XXX", the head-office branch.
 */
export const BIC_BARE_PATTERN = /(?<![\p{L}\d_<\/+=-])([A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)(?![\p{L}\d_>\/+=-])/gu;
/** The words that make a message about banking, for BIC_BARE_PATTERN. */
export const BANKING_CONTEXT = /\b(?:iban|bic|swift|bank(?:ing)?|transfer|wire|remit|payment|pay|account|beneficiary|routing|sort\s+code|deposit|transaction|banque|virement|überweisung|bonifico|banca|banco|transferencia)\b|\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b/i;

/**
 * A PIN or an access code under words that are not "PIN": "enter 0167 to
 * access the room", "the passcode to access the meeting is 6752", "your
 * unique code 1015", "your 4-digit pin, 8475", "access codes are: 3742",
 * "unique pins 3720, 9199 and 6769". PIN_CUED_PATTERN takes "PIN: 1234".
 */
export const PIN_WORDED_PATTERN =
  /\b(?:pass\s?code|access\s+codes?|security\s+code|unique\s+(?:code|pins?|identification\s+code)|identification\s+code|(?:4|four|5|five|6|six)[-\s]digit\s+(?:pin|code|passcode)|pins)\b(?:[^.\n\d]{0,30}?)(?:[:=]|\b(?:is|are|was|will\s+be)\b)?[ \t]*(\d{4,6})(?![\d.,]?\d)(?:(?:,[ \t]*|[ \t]+and[ \t]+)(\d{4,6})(?![\d.,]?\d))?(?:(?:,[ \t]*|[ \t]+and[ \t]+)(\d{4,6})(?![\d.,]?\d))?/gid;
/** "enter 0167 to access", "use 3159 to access the room", "Validate your
 *  identity using 2260", "set a 8731 for future access". */
export const PIN_VERB_PATTERN =
  /\b(?:enter|use|using|set|choose|type|key\s+in)\s+(?:(?:your|the|a|this)\s+)?(\d{4,6})\s+(?:to|for)\s+(?:(?:the|your|future)\s+)?(?:access|log\s*in|login|sign\s*in|unlock|open|enter|validate|verify|confirm|authenticate)\b/gid;

/**
 * The word PIN a step away from its digits: "PIN for entry: 8156", "update
 * the pin to 1550", "an individual PIN like 2552" (2026-10-31, ai4privacy
 * practice half). PIN_CUED_PATTERN wants the digits right after the label.
 */
export const PIN_LOOSE_PATTERN =
  /\bpins?\b(?:\s+for\s+[a-z]+(?:\s+[a-z]+)?|\s+(?:to|like|such\s+as|e\.g\.))\s*[:=]?\s*(?<![\d.])(\d{4,8})(?!\d)(?![.,]\d)/gid;

/**
 * A short number that is somebody's, by the word before it and the purpose
 * after it: "We will need your 3414 for verification", "send your 3670.",
 * "enter my 1908.", "remember your 3767 for future transactions". Four to six
 * digits, then the end of the sentence or what a code is for. "your 2024
 * report" is a year and lower-case words, and stays.
 */
export const NUMBER_POSSESSIVE_PATTERN =
  /\b(?:your|my)\s+(?<![\d.])(\d{4,6})(?=\s*(?:[.!?;]|$)|\s+(?:for\s+(?:verification|confirmation|security|login|access|future\s+transactions|identification|authentication)|when\s+logging|to\s+(?:log|sign|verify|confirm|access))\b)/gimd;

/**
 * Five digits where a place goes: "Those seeking healthcare services in
 * 85587", "If you're coming from 11515, we have", "our childcare facility at
 * 67573 New Devintown", "the 60265 area". After at, in, from or near, and
 * then the end of the clause, a capitalised town or a word for an area; a
 * count is followed by what it counts ("in 10000 cases"), and stays.
 */
export const ZIP_PLACE_WORD_PATTERN =
  /(?<=\b(?:at|in|from|near|within|around)\s+(?:the\s+)?)(\d{5}(?:-\d{4})?)(?![\d.,]\d)(?=\s*(?:[,;:?!)]|\.(?!\d)|$)|\s+(?:area|region|zone|district|premises|neighbou?rhood|vicinity|postcode|zip)\b|\s+\p{Lu}\p{Ll}+)/gmu;

/**
 * Business and tax numbers whose shape names their country:
 *   Swiss UID       "CHE-262.225.523", "CHE-013-110-910"
 *   EU VAT numbers  "IT77853424203", "DE123456789", "NL123456789B01"
 * A shape, a prefix and a fixed length, so they stand without a label.
 */
export const CH_UID_PATTERN = /(?<![\w-])CHE[-\s]?\d{3}[.\s-]?\d{3}[.\s-]?\d{3}(?![\w-]|\.\d)/g;
/** France's tax number, the numéro fiscal, in the groups the tax notice
 *  prints it in, two, two and three threes: "13 04 266 964 210",
 *  "00.01.654.707.793", "20-41-664-977-173" (open-pii-masking practice half,
 *  2026-11-02). It opens with 0 to 3. One separator throughout; a French
 *  phone goes in twos, so it never takes this shape. */
export const FR_TAX_GROUPED_PATTERN = /(?<![\w.,-])[0-3]\d([ .-])\d{2}\1\d{3}\1\d{3}\1\d{3}(?![\w]|[.,-]\d)/g;
export const EU_VAT_PATTERN =
  /(?<![\w-])(?:IT\d{11}|DE\d{9}|FR[0-9A-HJ-NP-Z]{2}\d{9}|ES[0-9A-Z]\d{7}[0-9A-Z]|NL\d{9}B\d{2}|BE[01]\d{9}|ATU\d{8}|PL\d{10}|PT\d{9}|SE\d{10}01|DK\d{8}|FI\d{8}|IE\d{7}[A-W][A-I]?|LU\d{8}|CZ\d{8,10}|SK\d{10}|HU\d{8}|RO\d{2,10}|EL\d{9}|GB\d{9}(?:\d{3})?)(?![\w-])/g;

/**
 * A VAT or tax number written with spaces under its label, which the shape
 * above cannot see: "VAT No: GB 123 4567 89", "USt-IdNr.: DE 123 456 789",
 * "P.IVA 123 4567 8901", "BTW-nummer NL 8597 1234 5B01" (realistic). The
 * label vouches for it; the scan asks for eight to fourteen digits.
 */
export const VAT_CUED_PATTERN =
  /\b(?:VAT(?:[ \t]+Reg(?:istration)?\.?)?(?:[ \t]*(?:No\.?|Number|Nr\.?|ID|#))?|USt-?Id(?:Nr\.?)?|Umsatzsteuer-?(?:Identifikationsnummer|ID)|TVA(?:[ \t]+intracommunautaire)?|N°[ \t]*TVA|P\.?[ \t]?IVA|Partita[ \t]+IVA|BTW(?:-?nummer|[ \t]*nr\.?)?|Momsnr\.?|Momsregistreringsnummer|NIP|CIF|ABN|GSTIN?)[ \t]*[:#.]?[ \t]*((?:[A-Z]{2}[ \t]?)?\d[\d \t.-]{6,18}[\dA-Z])(?![\dA-Za-z])/gd;

/**
 * A business's registration or tax number under its label, in the
 * languages VAT_CUED_PATTERN does not cover: "CVR 47 60 16 06", "org.nr.
 * 976 479 920", "Y-tunnus 1090479-1", "NIPC 509 228 410", "ח.פ. 514882301",
 * "사업자등록번호 214-87-55302", "统一社会信用代码 91440606MA52K7XQ3T" (realistic6
 * and realistic7 invoices, read 2026-11-11). A freelancer's company number
 * is the freelancer: a photographer's CVR is found from their name and back.
 * Digits in groups, seven to fourteen of them, or China's eighteen-character
 * code.
 */
const BUSINESS_ID_LABEL = String.raw`(?:CVR(?:-?nr\.?)?|[Oo]rg\.?[ \t]?nr\.?|[Oo]rganisasjonsnummer|[Oo]rganisationsnummer|[Oo]rg\.?[ \t]?nummer|Y-tunnus|NIPC|KvK(?:-?nummer)?|KVK(?:-?nummer)?|ח\.?[ \t]?פ\.?|ע\.?[ \t]?מ\.?|사업자(?:[ \t]?등록)?[ \t]?번호|统一社会信用代码|統一社會信用代碼|統一編號|统一编号)`;
export const BUSINESS_ID_LABELLED_PATTERN = new RegExp(
  String.raw`(?<![\p{L}\p{N}])${BUSINESS_ID_LABEL}(?![\p{L}])[ \t]*(?:[:：#]|是|為)?[ \t]*` +
  String.raw`(\d[\d \t.-]{5,18}\d(?:-\d)?|[0-9A-Z]{18})(?![\p{N}A-Za-z])`,
  "gdu",
);

/**
 * A national identity or tax number as a key in a log line or a query string:
 * "nip=6237471436", "snils=727-362-759 22", "ipn=2984401573", "tz=630111151",
 * "mynumber=4397 4414 1895", "adoazon=8412097735" (realistic6 and realistic7
 * dev logs, read 2026-11-11). The key names the number, so its shape is not
 * checked beyond eight to sixteen digits: "tz=+01:00", a time zone, has none.
 */
export const ID_LOG_KEY_PATTERN =
  /(?<![\w.-])(?:nip|pesel|regon|snils|inn|ipn|rnokpp|tz|teudat_?zehut|mynumber|my_number|kojin_?bango|adoazon|ado_?azonosito|taj|cpf|cnpj|rut|curp|rfc|dni|nie|nif|bsn|cnp|egn|oib|jmbg|emso|hetu|personnummer|cpr|fodselsnummer|amka|afm|tckn|tc_?kimlik|nik|ktp|aadhaar|pan|ssn|sin|nino|tfn|ird)["']?[ \t]*[=:][ \t]*["']?(\d[\d \t.-]{6,18}\d)(?![\d])/gid;

/**
 * A Japanese bank account: seven digits after the kind of account, 普通
 * (ordinary) or 当座 (current), or after 口座番号. "普通 4718263" (realistic2).
 */
export const JA_ACCOUNT_PATTERN = /(?:(?:普通|当座|貯蓄)(?:預金)?(?:口座)?|口座番号)[ \t]*[:：]?[ \t]*(?:No\.?[ \t]*)?(\d{7,8})(?!\d)/gud;

/**
 * A Spanish phone in its usual grouping and no country code: "612 48 39 75"
 * and "973 26 41 18", three and three pairs from 6 to 9, and "91 234 56 78".
 * Neither grouping is how a sum, a date or a code is written.
 */
export const ES_PHONE_PATTERN = /(?<![\d+.,/-][ \t]?|\d)((?:[6-9]\d{2}[ \t]\d{2}[ \t]\d{2}[ \t]\d{2})|(?:[89]\d[ \t]\d{3}[ \t]\d{2}[ \t]\d{2}))(?![ \t]?[\d.,/-]?\d)/gd;

/**
 * A phone under the word for it in the rest of the forty languages, or the
 * verb before it: "telèfon 973 26 41 18", "Tlf 413 77 290", "puh 045 612
 * 9930", "meine nummer ist 0157/23 98 41 06", "mi cel es 55 3847 2916", "contacto 217 904 336", "ring på 31 54 88
 * 20", "hívj a 06 70 331 2846", "T. 02-3142-7789", "טל׳ 03-5612290", "手机号从138
 * 1123 5590", "โทร 02-391-8842", "дзвони йому 067 418 22 93" (realistic5).
 * PHONE_CUED_INTL_PATTERN has the benchmark's first seven.
 */
export const PHONE_CUED_WORLD_PATTERN =
  /(?:(?<![\p{L}])(?:tel[èe]fon|telem[óo]vel|telefone|celular|cel|contacto|contato|tlf\.?|tlfn?r\.?|puh\.?|puhelin|hp|no\.?[ \t]+hp|wa|whatsapp|(?:meine|mein|min|mijn|mitt)[ \t]+(?:handy)?nummer(?:[ \t]+(?:ist|er|is|är))?|mi[ \t]+(?:cel|n[úu]mero)(?:[ \t]+es)?|meu[ \t]+n[úu]mero(?:[ \t]+[ée])?|ring(?:[ \t]+(?:meg|mig|me|oss|deg|dig))?(?:[ \t]+(?:p[åa]|til))?|zadzwo[ńn](?:[ \t]+(?:do[ \t]+mnie|mi))?(?:[ \t]+(?:na|pod))?|dzwo[ńn][ \t]+(?:na|pod)|zavolej(?:te)?(?:[ \t]+mi)?(?:[ \t]+na)?|zavolaj(?:te)?(?:[ \t]+mi)?(?:[ \t]+na)?|volej(?:[ \t]+mi)?[ \t]+na|ruf(?:[ \t]+mich)?(?:[ \t]+an)?(?:[ \t]+unter)?|rufen[ \t]+Sie(?:[ \t]+mich)?(?:[ \t]+an)?(?:[ \t]+unter)?|erreichbar[ \t]+unter|(?:festnetz|handy)(?:nummer)?|תתקשרי?(?:[ \t]+אליי?)?[ \t]+ל-?|svarer[ \t]+ikke[ \t]+p[åa]|svarar[ \t]+inte[ \t]+p[åa]|h[íi]vj(?:[ \t]+a)?|nås[ \t]+p[åa]|call[ \t]+(?:[\p{L}.]+[ \t]+){0,3}(?:at|on)|en[ \t]+number|na[ \t]+number|naya[ \t]+no\.?|T\.|Tel|Mob\.?|טל[׳']?|טלפון|נייד|電話|电话|手机号?(?:码)?(?:从|是|为)?|전화(?:번호)?|휴대폰|โทร(?:ศัพท์)?|тел\.?|телефон|номер|дзвони(?:[ \t]+[\p{L}]+)?|звони(?:[ \t]+[\p{L}]+)?)(?![\p{L}])(?:[ \t]+(?:[ée]|es|is|ist|er|är|je|jest)(?:[ \t]+(?:o|a|el|la))?(?![\p{L}]))?[ \t]*[:：=.]?[ \t]*)(\+?\(?\d[\d ()./-]{5,18}\d)/giud;

/**
 * Mobiles and landlines whose grouping names their country, with no word in
 * front: Chinese "138 1123 5590", Indian "98110 45672", Dutch "06-41829307"
 * and "06 2918 4473", Brazilian "(19) 3251-7740", Russian "8 (961) 447-05-19",
 * Ukrainian "067 418 22 93", Swedish "070-990 12 47" and "08-649 30 12",
 * Hungarian "06 70 331 2846", Israeli "04-6981123", Pakistani "021-34567890",
 * Philippine "(02) 8721 4430". Each of those groupings is a phone's alone.
 */
export const PHONE_NATIONAL_SHAPED_PATTERN =
  // Not inside a token: "req-…-a059-07998751face" is a request id.
  /(?<![\d+./-][ \t]?|[\dA-Za-z_-])(1[3-9]\d[ \t]\d{4}[ \t]\d{4}|[6-9]\d{4}[ \t]\d{5}|06[- ]\d{8}|06[ \t]\d{4}[ \t]\d{4}|\(\d{2}\)[ \t]?9?\d{4}-\d{4}|8[ \t]?\(9\d{2}\)[ \t]?\d{3}-\d{2}-\d{2}|0(?:39|50|6[3-8]|7[0-9]|9[1-9])[ \t]\d{3}[ \t]\d{2}[ \t]\d{2}|0\d{1,3}-\d{2,3}[ \t]\d{2}[ \t]\d{2}|06[ \t][237]0[ \t]\d{3}[ \t]\d{4}|0[2-489]-\d{7}|0\d{2}-\d{8}|\(0\d\)[ \t]\d{4}[ \t]\d{4})(?![ \t]?[\d.,/-]?\d|[A-Za-z_])/gd;

/**
 * A passport or national ID number written alone, one or two letters and
 * seven or eight digits: "GW5666616", "U0387769", "A04806905". Rare in real
 * text (fourteen in 130,000 prompts, most of them IDs); the shapes it shares
 * are a patent ("US1446758") and a Windows update ("KB4489899"), refused by
 * prefix in findStructured.
 */
export const PASSPORT_SHAPE_PATTERN = /(?<![\w\-])([A-Z]{1,2}\d{7,8})(?![\w-])/g;
/** A French passport: two digits, two letters, five digits, "21RX26694"
 *  (open-pii-masking practice half, 2026-11-02). None in 109,457 real and
 *  test texts. */
export const FR_PASSPORT_PATTERN = /(?<![\w-])\d{2}[A-Z]{2}\d{5}(?![\w-])/g;

/**
 * An identity, tax or social-security number under its Portuguese label:
 * "número fiscal (046754557)", "Número do seguro social: 278431889", "número
 * de cartão de cidadão 79457187 5", "documento de identificação (75097070 8)",
 * "NIF 123456789", "CPF 123.456.789-09". The labels CUED_ID_PATTERN knows are
 * the other European languages'; these are Portugal's and Brazil's.
 *
 * And the passport and the driving licence by their other names, with the
 * form's "(se aplicável)" before the value: "passaporte LU273989", "licença
 * de condução EE-673264", "carteira de motorista ED-435686", "Número do
 * passaporte (se aplicável): ME638191" (moreLanguages practice half,
 * 2026-11-02).
 */
export const PT_ID_CUED_PATTERN =
  /(?<![\p{L}\d])(?:n[úu]mero\s+(?:de\s+|do\s+|da\s+)?(?:identifica[çc][ãa]o\s+fiscal|contribuinte|fiscal|seguran[çc]a(?:\s+social)?|seguro\s+social|cart[ãa]o\s+de\s+cidad[ãa]o|passaporte|utente|identidade|carta\s+de\s+condu[çc][ãa]o|habilita[çc][ãa]o)|cart[ãa]o\s+de\s+cidad[ãa]o|documento\s+de\s+identifica[çc][ãa]o|bilhete\s+de\s+identidade|carta\s+de\s+condu[çc][ãa]o|passaporte(?:\s+n[úu]mero)?|(?:licen[çcs]a|carteira|passe)\s+de\s+(?:condu[çc][ãa]o|motorista)|NIF|CPF|RG|CNH)(?![\p{L}\d])(?:\s*\(se\s+aplic[áa]vel\))?[\s:()º°.]*(?:(?:é|e|em|n\.?º)\s+)?[(\s]*([A-Z0-9](?:[A-Z0-9.\-/]|\s(?=\d))*[A-Z0-9])(?![\p{L}\d])/giud;
