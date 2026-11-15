import { sha256Hex } from "./redactionMap.js";
import { addStructuredRedactions } from "./redactionStructured.js";

/**
 * Which redaction build this machine is running, as a number.
 *
 * The same three stages run in two places -- this Worker, and the Nitro
 * enclave the Worker hands ordinary chats to -- from the same source, built
 * and deployed separately. Nothing said which build either one was on, and on
 * 2026-09-23 that cost an afternoon: a fix to the date-of-birth stand-in was
 * committed, deployed to the Worker three times, verified in the uploaded
 * bundle, and still did not change a single answer, because the value a user
 * actually receives is minted inside the enclave and the enclave was running
 * an older image. Every signal available said the deploy had worked.
 *
 * ── Why a probe, and not a version string ──
 *
 * A git sha would say which commit a build came from, which is a fact about
 * the deploy pipeline. The question worth answering is what the code does:
 * two builds that redact identically are the same build for every purpose
 * anybody cares about, and two that do not are different however their
 * version strings compare. So this runs a fixed page of invented values
 * through the stages that need no model and hashes the map that comes out.
 * The value changes when, and only when, an answer changes.
 *
 * ── Why these values ──
 *
 * One of each kind the structured stage claims to find, so a detector that is
 * missing, added, loosened or tightened moves the number -- and written the
 * way they were in the messages that exposed each one. Invented, and nobody's:
 * a fingerprint that had to be kept secret would be no use on a health check.
 *
 * Nothing here calls a model, so the name stage is deliberately out. It would
 * make the fingerprint depend on what Workers AI answered this second, and a
 * number that changes on its own says nothing about the build.
 */
const PROBE = [
  "email maria.whitfield@northgate-legal.co.uk about the 4111 1111 1111 1111 card",
  "iban ES91 2100 0418 4502 0005 1332, sort code 04-00-72, ni number QQ123456C",
  "call 020 7946 0142 or +44 7700 900123, she is at 42 Wexford Street, SW1A 2AA",
  "dob 1988-03-14, date of birth 14 March 1988, vin 1HGCM82633A004352",
  "box 2001:0db8:85a3:0000:0000:8a2e:0370:7334 on db01.internal.acme.com, 10.0.4.7",
  "wallet 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa, key sk-live-abcdefghijklmnopqrstuvwx",
  // The labelled values of #85. Without a line for them the fingerprint did
  // not move when they shipped, and a Worker on the new rules and an enclave
  // on the old ones read as a match.
  "Customer ID: CUST20794343 Swift BIC-code: MQOIUSOH336 BBAN: TXQZ63884455701918 Kreditkortssäkerhetskod: 280",
  "Account PIN: 9642 Passwort: X%se8RO8QV5!fSdd User Name: connor_854 Förarbrevsnummer: QA37887457",
  "Street Address: 7463 Katrina Keys Telefon: 070-123 45 67 SSN: ZZ 883165 T Numéro de carte de crédit : 3014 5455 3834 7",
  "Customer IP Address: 134.95.225.93",
  // A number, a heading and a street word on three lines are not a street.
  "Odometer in/out 79,770/79,779\nBILL TO\nSummit Mutual Insurance",
  // 2026-10-02/03: none of these moved the number when they shipped, so a
  // Worker on the new rules and an enclave on the old read as a match while
  // the live site still let every one of them through (checked by hand).
  // Invisible characters in a pasted card; a verb after a phone label; Hindi.
  "card 4539​ 1488​ 0343​ 6467. Mon numéro de téléphone est 01 23 45 67 89. मेरा फोन नंबर 98765 43210 है",
  // A street named for a person; a user name and an unlabelled password.
  "office Kurt-Oster-Straße 145. Hello Laisha_Koss58, use pDI_DYJc7Idx to log in",
  // A number read out, dictated, and wrapped across a line.
  "card 5 1 0 5 1 0 5 1 0 5 1 0 5 1 0 0, call me on zero seven seven zero zero nine zero zero one two three, or at (713) \n345-7373 today",
  // Values under a field name.
  '{"account_number": "0388412907", "pin": "7302"}\nname,card_number,zip\nDana,6381973478101820,90210',
  // And what is left alone: a commit is not a phone number.
  "commit bf2444630449 fixed it",
  // 2026-10-03, from real prompts and logs: an event, a product and a GC log
  // are not an address or an ID, and a block id is not a card.
  "the 2018 UCI Track Cycling World Championships on Server 2003, Server 2008 R2, ParOldGen: 57435641K->57435322K(57435648K) blk_2904134648927436267",
  "use MobileNetV3; string password = textBox2.Text; private void Delete_Click(object sender)",
  // 2026-10-04: a password of letters alone is taken; a code name is not.
  "password: PVJjvBMcjGna, then call OkHttpClient and Blob_MethodRefSig_294 at loss = 277167.4375",
  // User names with no cue, streets with no number, and the French cue.
  "Best, Gaston84 and Jacques.Schneider, at Skye Crossing or 856 Bridget Dale in Leeds, rendez-vous à Fritz Street; not Vector3 or Times Square",
  // Phones, accounts, flats and roads in other languages.
  "contacter au +61.38.625.4974, sent to 40073954, moved Apt. 326, Camino del Villar 88, Rijndijk 41, mijn postcode is 8166 KZ, पता: Dhaulha Road 670",
  // IDs, bank codes, PINs and login-log addresses; an encyclopedia's birth date.
  "deine AT8126685, C2TZXGY7LR, CHE-738.689.203, IT77853424203, GW5666616, include KRJUPTS2XXX, passcode is 6752, from 173.234.31.186 port 38926; Taylor Swift (born December 13, 1989) is an American singer; CH3CH2OH",
  // 2026-10-05: Japanese, Chinese, Korean, Arabic and Portuguese.
  "上飯田東町 2-20-33、郵便番号は626-0042。通站路 523号（邮编 510235）。마장로 407에, 우편번호: 47856. رقم الهوية: 1350406789 الجوال: 583009316 الرمز البريدي 86735. número fiscal (046754557); 走路1, 知道2022",
  // Record numbers under new labels and by prefix, a quoted user name, a session cookie.
  "Vehicle Identifier: MVPZNRZSHH8G96XFG, beneficiary number L955657302, MRN-321180, user 'geraldine_2143', user_session=zx7m9n2pq3; registration number 2024",
  // A password with what it is for, and a national number by its cue.
  "the password for the patient portal is Rainbow@2025; requires a password, Sarah1995; contactable at (02)-6378-6141 or 07-4584-7618; Version 02.345.6789",
  // 2026-10-06: record numbers by shape, plates in groups, VINs after a bare
  // label, the second of two labelled IPs, two national phone shapes.
  "Technician: Xs-85415, T-328550-A, R886734-Bc, C231-1842-334, ECOM-215133; License Plate: BH 2547 FK; for vehicle 0WXA7UD9DJHLTXY7H; IP addresses 174.146.142.119 and 55.237.8.40; (0312) 456 7890, 0909 8790437, reached at 8706-8391; Co-60, COVID-19",
  // Labels learned from benchmark misses (redactionLearned.ts).
  "Device ID: 4f9c2a7e-1123; the device identifier MK-883-21Q; identifier: S-1-5-18",
  // 2026-10-07: more learned labels, a reference after a record word, French
  // pairs; and what stays: an invoice number, a public case.
  "**Phone Number:** 0694 1870; Policy: PLX-77310452; (ID E-20931); Mon numéro : 06 12 34 56 78; Invoice INV-820; case C-283/14",
  // 2026-10-08: values a few words from their label, a short IPv6 ending a
  // sentence; and what stays: a server's address, a list after a comma.
  "the IP address recorded for this event is 217.134.89.179, the API key for the service is tP2nX8jL7mB1kW0hV5Q9c4dUzX2wY6tR, the http cookie csrf_protection=gk27jxpqz13m, your user name is victormaya, license plate, GKX 327, customer id, CUS834721, ends 2a02:4d60::abcd. The IP address of our server is 52.14.1.9; carry your passport, Form I-94",
  // A town ending a sentence, not a street with a number: "Fore Street"
  // goes, "Exeter. GCS 13" stays.
  "found outside the shop on Fore Street, Exeter. GCS 13, BM 2.1, given glucagon",
  // 2026-10-23: two French phones side by side, and opening hours after a
  // phone, which are not part of it.
  "Tél : 06 12 34 56 78 06 98 76 54 32, appelez le 01 23 45 67 89 24h/24 ou call 020 7946 0142 24/7",
  // And left alone: an image at a pixel density, and code around a password.
  "icon@2x.png; password = PasswordField('password', validators=[DataRequired()]); {password}@{host}/{database}",
  // 2026-10-24: national IDs and streets in the UAE, Israel, Russia,
  // Indonesia and Vietnam, and a Polish postcode after its street.
  "رقم الهوية 784-1990-0123456-8؛ ת\"ז 203456785; СНИЛС 158-394-726 13; NIK 3204124508910003; рядом ул. Пушкина, д. 7; ở số 45 Nguyễn Huệ, Jl. Diponegoro No. 8; ul. Polna 3/12, 31-042 Kraków",
  // Technical writing: an install line's package id, a Kubernetes lease in
  // hex, and "generated", which opens with the given name Gene.
  "winget install 9NQ7512CXL7T -e; apiserver-1dfef752bcb36637d2763d1868; the username is generated",
  // Records: an XML password without its closing tag, an HTML label that is
  // not a password, a card a few words after its label, a Field/Value table.
  "<Password>X9k$LmP3zQ8</Password> <label for=\"password\">Password</label> the credit debit card, 5187 3495 6702 1239, to buy",
  "| Field | Value |\n|---|---|\n| VIN | JN1FV8G78CJ123456 |\n| Mileage | |",
  // 2026-10-22: a French social security number with a wrong key under its
  // label, a British vehicle reg, a password with where it is in between, a
  // postcode after the floor and flat.
  "numéro de sécurité sociale est 1 92 11 13 055 017 40; Vehicle reg: MV21 KHT; the wifi password at the cafe is Plum!River77; Calle de Alcalá 120, 2º izq., 28009 Madrid",
  // 2026-10-23, from real prompts: an article's birth date with its birthplace
  // inside the brackets, a lottery draw, a class in a stack trace and a Python
  // slice are left alone; the IPv6 address beside them still goes.
  "Carl Rimmer (born 29 April 1986 in Banbury, England) is an English rugby league player. STARS 05 10 01 15 19 24 33 STARS; at jdk.internal.reflect.NativeMethodAccessorImpl.invoke0; face[1::2] on fe80::1",
  // Fields of a schema and public Ethereum addresses are left alone; a user
  // name and a wallet of the writer's own still go.
  "Entities: Patient_Name, Appointment_Date, Doctor_Name; WETH 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2; mod Laisha_Koss58, wallet 0x0d4890ecEc59cd55D640d36f7acc6F7F512Fdb6e",
  // 2026-10-23, the shapes the second realistic hold-out found missed (in
  // values of their own): labels the engine did not know, and two ways of
  // writing a street.
  "Tel. 0176 55190342; 手机177-0381-5526; 계좌번호 352-0917-4468-03; NHC 55302871; 센텀중앙로 55번길 7, el portal de calle Goya 48",
  // 2026-11-14, the leak hunt: a fullwidth email, a pw label, a password
  // with a backslash, and a JWT over 200 characters.
  // 2026-11-14, round 3: an IP under a JSON key, a signature's phone
  // label, Portuguese and Hindi accounts, an Arabic road with its town.
  // Round 3b: a lowercase IBAN, a street in capitals, a car plate, a CVV.
  "iban de89370400440532013000; 1507 BAY RIDGE PKWY, BOISE ID 83702; car plate SYF-2270; card 4111 1111 1111 1111 cvv 357",
  '{"client_ip":"108.42.56.58"}\nT: 479-380-920\nconta 63049-8, खाता 557249280252, طريق العليا 794، الرياض 01479',
  "ping @sarahchen on slack; ｊａｎｅ＠ｇｍａｉｌ．ｃｏｍ; pw: 7Fj#kL9!; password: C:\\Users\\x9Kq!2; token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZW1haWwiOiJqb2huLmRvZUBleGFtcGxlLmNvbSIsImlhdCI6MTUxNjIzOTAyMiwicm9sZSI6ImFkbWluIiwic2NvcGUiOiJyZWFkIHdyaXRlIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
].join("\n");

/**
 * Bumped when a change makes the stages replace LESS than before, which the
 * map cannot show: a false positive removed leaves the same map on every line
 * that still has a replacement, so a Worker with the fix and an enclave without
 * it would fingerprint the same. Add a probe line for the case and bump this.
 */
// The second line names what the probe cannot show: 256 map entries where
// there were 64, and a name stage that reads initials and drops document
// words. Neither shows in a page of a dozen values.
const PROBE_REVISION = "2026-10-05 Japanese Chinese Korean addresses, Saudi IDs phones postcodes, Portuguese ID labels"
  + "; 256 map entries, names by initials, document words not names"
  + "; 2026-10-06 organisations on request, French titles and initials, the name gate reads spaced commas"
  + "; 2026-10-07 long documents' names read on a clock, unsure lone words outside English not names"
  + "; 2026-10-08 organisations all, medical mode (dates, ages over 89, towns, care facilities), model places whole words only"
  + "; salted stand-ins with no word of their value, UK and European medical records, a species is not a person"
  + "; package ids on install lines, base58 with one case, user names that are words"
  + "; XML passwords without their tag, HTML labels not passwords, table rows not headers, Unspecified not a value"
  + "; 2026-10-22 ordinary words and titles in ten languages not names"
  + "; 2026-10-23 a title the name model took in with a name stays visible"
  + "; 2026-10-23 article birth dates in more forms, lottery draws not French phones, stack-trace classes not hosts, Python slices not IPv6"
  + "; schema fields among identifiers not user names, public Ethereum contracts and test accounts not wallets"
  + "; images at a pixel density not emails, code around a password not a password"
  + "; very famous people asked about not names (Wikidata, 60 Wikipedias), unless the writer knows them"
  + "; 2026-10-24 a title on its own not a name, Spanish French German Italian Dutch titles off a name"
  + "; 2026-11-07 cues held to the word lists, tails of Hebrew words not names"
  + "; 2026-11-14 names located in any spacing or case, months and coordinated words as people, lower-case cues beside capitals, the latest message read whole"
  + "; 2026-11-14 round 3: IPs under JSON and header keys, one-letter signature phone labels, Portuguese and Hindi accounts, Arabic roads, stand-ins that carry no name in the text, record labels as knowing a famous name"
  + "; round 3b: lowercase IBANs past the hex guard, streets in capitals, car and my plate, lowercase given names where a person stands, email stand-ins with free halves, CVVs of their own length, a word whose half was taken gets its own";

/** Computed once. The stages are pure and the input is a constant, so the
 *  answer cannot change without a redeploy -- which is the whole point. */
let cached: string | null = null;

/**
 * Twelve hex characters of the map the probe produces.
 *
 * Short because it is read by a person comparing two of them, and a full
 * digest is worse at that than a number the eye can hold. Twelve is far more
 * than enough: this is a change detector between two known builds, never a
 * defence against somebody constructing a collision.
 */
export async function redactionFingerprint(): Promise<string> {
  if (cached) return cached;
  const map = await addStructuredRedactions({}, PROBE, PROBE);
  // Sorted: the map is an object, and two builds that found the same values in
  // a different order are the same build. The values found, not their
  // stand-ins: those are salted per process (see pickFake), so two machines
  // running the same build draw different ones.
  const rows = Object.values(map).sort().join("\n");
  cached = (await sha256Hex(`${PROBE_REVISION}\n${rows}`)).slice(0, 12);
  return cached;
}
