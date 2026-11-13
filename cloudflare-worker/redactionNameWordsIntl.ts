/**
 * Ordinary words in the other languages the name stage reads, which its NER
 * models hand back as people.
 *
 * Measured on open-pii-masking-500k (300 documents a language, 2026-10-05):
 * the English filters in redactionNameWords.ts left 184 words in German that
 * were nobody — "Hallo" 65 times, then "Ihre", "Ich", "Liebe", "Danke",
 * "Bitte" — 100 in Dutch ("Hallo", "Beste", "Geachte"), 76 in Italian
 * ("Ciao", "Potresti", "Sì") and 49 in French ("Bonjour", "Cher"). A
 * greeting, a pronoun, a polite word or a verb that opens a sentence is
 * capitalised there, and German capitalises every noun ("Daten", "Adresse",
 * "Wohnung"), so a tagger reading capitals as names reads all of these.
 *
 * Lower case, compared lower case.
 */
import { GIVEN_NAMES } from "./redactionGivenNames.js";

const WORDS = `
gruppe leute hallo hello hi hey hoi hé hej moin servus grüezi tschüss ciao salve ehi buongiorno buonasera buonanotte
bonjour bonsoir salut coucou allô hola buenos buenas adiós olá oi bom boa tchau goedendag goedemorgen
goedemiddag goedenavond dag doei liebe lieber liebes sehr geehrte geehrter geehrtes beste geachte
caro cara cari care gentile gentili egregio egregia cher chère chers chères querido querida queridos
estimado estimada estimados prezado prezada senhor senhora signor signora signore madame monsieur
mademoiselle mevrouw meneer herr frau damen herren dame herrn
danke dankeschön bitte vielen dank merci grazie gracias obrigado obrigada dankjewel bedankt alsjeblieft
alstublieft prego per favore s'il vous plaît por favor veuillez pouvez-vous pourriez-vous potresti
potrebbe puoi può posso possiamo vorrei volevo könnten könntest kannst können würden würdest
kunnen kunt zou zouden kun puede podría podrías puedes pode poderia
ich du er sie es wir ihr ihre ihr ihren ihrem ihrer ihres mein meine meinen meinem meiner dein deine
deinen deinem deiner unser unsere euer eure sein seine je tu il elle nous vous ils elles mon ma mes
ton ta tes son sa ses notre nos votre vos leur leurs io tu lui lei noi voi loro mio mia miei mie tuo
tua suo sua nostro nostra vostro vostra yo tú él ella nosotros vosotros ellos ellas mi mis tu tus su
sus nuestro nuestra eu ele ela nós eles elas meu minha teu tua seu sua nosso nossa ik jij je hij zij
wij jullie mijn jouw zijn haar ons onze uw hun
ja nein jawohl doch oui non si sì no sim não nee jazeker natuurlijk tuurlijk certo certamente claro
genau klar sicher bien bene benissimo perfetto perfekt parfait perfecto perfeito prima super toll
geweldig fantastisch fantastico fantastique génial genial ok okay
und oder aber denn weil wenn dass also auch noch schon nur sehr hier dort heute morgen gestern
et ou mais donc car parce que quand aussi encore déjà très ici aujourd'hui demain hier
e o ma però perché quando anche ancora già molto qui oggi domani ieri y pero porque cuando también
todavía ya muy aquí hoy mañana ayer mas quando também ainda já muito aqui hoje amanhã ontem
en of maar want omdat als ook nog al heel hier vandaag morgen gisteren anders waarom waaronder graag
der die das den dem des ein eine einen einem einer le la les un une des du il lo gli uno una el los
las unos unas o os um uma de het een
was wer wie wo wann warum welche welcher quoi qui comment où quand pourquoi quel quelle che chi come
dove quando perché quale qué quién cómo dónde cuándo cuál o que quem onde wat wie hoe waar wanneer welk
welke
ecco sono siamo sei è era ho hai abbiamo dobbiamo devo deve sembra sapevi contiene richiesta
bin bist ist sind war waren habe hast hat haben hatte gibt geht gehen kann muss soll will möchte
suis es est sommes êtes sont ai as avons avez ont était cela ceci ça voici voilà rappel
soy eres es somos son estoy está están tengo tiene hay sou é somos são estou está tenho tem há
ben bent is zijn was waren heb hebt heeft hebben gaat ga kan wil moet
daten adresse hilfe nachricht nachrichten leute wohnung zustimmung telefonnummer tanz vorsätze
vorfahren ruhestandsgeld spielentwickler unterzeichnet information informationen frage fragen
antwort termin rechnung konto bank kunde kunden mitarbeiter projekt bericht unterlagen dokument
dokumente formular anfrage bestellung lieferung zahlung betrag datum uhrzeit ort stadt land
straße hausnummer postleitzahl geburtstag geburtsdatum alter geschlecht name vorname nachname
männlich weiblich mann frau kind kinder familie freund freundin kollege kollegin team firma
gruppe schule universität arzt ärztin patient patientin
zorg vrouw man kind vriend vriendin jarige god leeftijd geslacht adres telefoon nummer naam
indirizzo età sesso maschio femmina maschile femminile nome cognome progetto richiesta telefono
numero data ora città paese amico amica famiglia medico paziente
masculin féminin homme femme personnelles personnel thème rencontre adresse téléphone numéro
nom prénom âge sexe ville pays ami amie famille médecin patient beaucoup ouf
masculino femenino hombre mujer dirección teléfono número nombre apellido edad sexo ciudad país
amigo amiga familia médico paciente endereço telefone nome sobrenome idade sexo cidade amigo
हैलो हेलो नमस्ते नमस्कार हाय आपका आपकी आपके मेरा मेरी मेरे मैं हम तुम आप वह यह धन्यवाद कृपया फॉर्म
दादाजी दादी नानाजी नानी पिताजी माताजी भाई बहन दोस्त
హాయ్ హలో నమస్కారం నమస్తే నేను మేము మీరు మీ మా నా అతను ఆమె ధన్యవాదాలు దయచేసి స్నేహితుడు
leute gruppe gedicht pflanzen großvater lassen lieblingskünstler
otoño simulacro contactar alguien espero llama
appeler congratulazioni contattare chiamami completare nel dei capodanno aiuto aiutarlo
hartelijk dit aandacht alle doel deel doelstellingen doorgehaald
हमें हमारे आशावाद इंद्रधनुष వాటర్ కలర్ వర్సెస్ అరే నాకు 귀하의 웨비나 フォロワー
professorin professeure sénateur mme mtre signorina secretaria alcalde presidenta barones gravin
korporaal सुश्री श्रीमान श्रीमती ちゃん
od át stä इस सैंपल्स הפגישה engels urbanos 로그인이 여사
`;
/* The last line, from realistic5's false alarms (2026-11-02):
 * Polish "from", Hungarian "through", the end of Finnish "PDF:stä", Hindi
 * "this" and "samples", Hebrew "the meeting", Dutch "English", Spanish
 * "urban", Korean "login" with its particle and the honorific 여사. */
/* The last eight lines, from the name stage's false alarms on
 * namesMultilingual and namesEastAsia practice rows (2026-10-22): each
 * taken as a person, and checked against 30,248 labelled names in the
 * practice halves of every labelled corpus here, where none of them is a
 * word of a name. Left out because they are: Sohn, Mom, Graaf, Meister,
 * Kumar, Kumari, Chan, Anders and Cher. The last two lines are titles; as
 * the first word of a name they are taken off it ("Barones Mathysen-Gerst"
 * -> "Mathysen-Gerst") the way a greeting is, by withoutGreeting. */

/*
 * The words of a judgment, a contract or a ministry's letter, in the same
 * languages. German capitalises every noun and every language capitalises the
 * word that opens a sentence, so "Urteil", "Hersteller", "Klägerin",
 * "Comissão", "Ministro", "Allerdings" and "Contudo" came back as people from
 * EU legal text (MAPA, 2026-10-05: in German, 84% of what the name stage took
 * in one validation sample was a word like these). Nouns of courts, law and
 * procedure, the parties, the words that join an argument, ordinals and the
 * names of languages. Nothing here is a common surname: Richter, Schutz,
 * Kaiser and Bauer are left out on purpose. A phrase is taken only when every
 * word of it is a listed word, so "Maria da Silva" is still a person.
 *
 * The last three rows are Polish, Turkish and Indonesian greetings, sign-offs
 * and titles ("Pani", "Pozdrawiam", "Merhaba", "Bapak"), 2026-10-24, none of
 * them a word of the 64,326 names labelled in the practice corpora. Not "pan",
 * which is a surname.
 */
const DOCUMENT_WORDS = `
urteil urteile urteils urteilen beschluss beschlusses entscheidung entscheidungen gericht gerichts
gerichtshof gerichtshofs generalanwalt generalanwältin schlussanträge schlussanträgen kammer senat
richtlinie richtlinien verordnung verordnungen vorschrift vorschriften bestimmung bestimmungen gesetz
gesetzes gesetze artikel absatz abs randnummer rn nummer buchst unterabsatz anhang anlage erwägungsgrund
recht rechts rechtssache rechtssachen rechtlicher rechtliche rahmen verfahren verfahrens verfahrensregel
vorlagefrage vorlagefragen vorabentscheidung vorabentscheidungsersuchen sachverhalt ergebnis
zwischenergebnis würdigung auslegung wortlaut wortlauts zweck ziel ziele systematik kontext
klage klagen klagegrund klagegrundes klägerin kläger beklagte beklagter beklagten streithelferin
rechtsmittel rechtsmittelführerin antrag anträge erwiderung gegenerwiderung stellungnahme erklärungen
schriftliche mündliche verhandlung kosten tenor gründe satzung kommission rat parlament union
mitgliedstaat mitgliedstaaten bundesrepublik regierung ministerium behörde behörden verwaltung
hersteller herstellern unternehmen unternehmens gesellschaft verbraucher arbeitnehmer arbeitgeber
untersuchung stichprobe kategorie anzahl umstände umstand stützung eröffnung vergabe kriterien
statistiken stellen schulen stipendien lernen bildung pflicht pflichten würde sache regel regeln
allerdings ferner konkret somit sicherlich tatsächlich daher jedoch insbesondere zudem außerdem
folglich demnach hingegen vielmehr nämlich schließlich zunächst sodann ebenso gleichwohl indessen
erstens zweitens drittens viertens fünftens sechstens zwischen zwecks bevor niemand gegenteil ohne
zweifel dieser diese dieses unter verkündet abgewiesen
deutsch englisch französisch spanisch italienisch portugiesisch polnisch rumänisch niederländisch
acórdão acórdãos tribunal tribunais juiz juíza advogado advogada geral conclusões conclusão
artigo artigos diretiva diretivas regulamento regulamentos decisão decisões processo processos
recorrente recorrida recorridas demandante demandada estado estados membros república comissão
conselho parlamento ministro ministra ministério diretor diretora pedido pedidos questão questões
prejudicial lei leis direito direitos constituição considerando contudo todavia porém portanto
assim além igualmente tanto foram ainda primeiro segundo terceiro quarto quinto
arrêt arrêts cour juridiction directive directives règlement règlements décision décisions procédure
requérant requérante défendeur défenderesse avocat générale conclusions traitement article articles
alinéa paragraphe point considérant commission conseil ministre ministère état états membres mesure mesures
toutefois cependant néanmoins donc ainsi partant ensuite enfin d'abord premièrement deuxièmement
sentencia sentencias juez jueza abogado tribunal directiva reglamento comisión comisario consejo
ministro ministerio artículo artículos apartado procedimiento recurrente demandado demandada cuestión
cuestiones prejudicial derecho ley estado miembros véase otras otros asimismo además embargo
sentenza sentenze corte giudice direttiva regolamento commissione consiglio ministro ministero
articolo articoli paragrafo procedimento ricorrente resistente questione questioni pregiudiziale
diritto legge stato membri fatti rigetto inoltre peraltro infatti tuttavia pertanto quindi
cordialement cordiali saluti distinti atenciosamente cumprimentos grüßen grüße empfänger empfängerin steuer-id
rappresentata deriverebbe da
arrest uitspraak hof rechter richtlijn verordening commissie raad minister ministerie artikel lid
procedure verzoeker verweerder vraag vragen prejudiciële recht wet lidstaat lidstaten echter
bovendien derhalve dus
pani państwo pozdrawiam pozdrowienia szanowny szanowna szanowni witam dziękuję proszę zwrot
merhaba sayın bey hanım saygılarımla teşekkürler selamlar
bapak ibu yth terima kasih hormat kepada
`;

/** The words that open a question or count something, capitalised as a
 *  sentence's first word: "Wie viele Grand-Slam-Titel…", "¿Cuántos…".
 *  2026-10-24. Checked against the 64,326 person values labelled in the
 *  practice corpora: chi, qui and come are names there, and are left out. */
const QUESTION_WORDS = `
wie viele wieviel welche welcher welches warum wann woher wohin wer wen wem wessen manche mehrere
cuántos cuántas cuánto cuánta cómo cuándo dónde quién quiénes cuál cuáles qué
combien comment quand où quoi quel quelle quels quelles pourquoi
quanti quante quanto quanta quando dove quale quali perché
quantos quantas como onde quem qual quais porque
hoeveel hoe wanneer waar wat welke waarom
`;

/** The words a request to an assistant opens with in the other forty
 *  languages: write, translate, explain, sum up, help, check, compare, make,
 *  tell, fix, count; why, how, who, which, when, where; hello, thanks,
 *  please, I, my. Capitalised as the first word, the taggers read them as
 *  people: "Kirjoita lyhyt esitelmä", "Terangkan beza", "Spiegami",
 *  "Hjælp mig" (realistic5, 2026-10-24). Written by hand, and checked
 *  against the person values labelled in the practice corpora and the
 *  hold-outs, so "Anh", "Dona", "Edit", "Chi", "Com", "Saya", "Kita" and "Bila" are left out. */
const REQUEST_WORDS = `
kirjoita laadi käännä selitä tiivistä auta tarkista vertaa tee luo kerro anna korjaa listaa laske muotoile ehdota
kumpi mikä miksi miten kuka mitä missä milloin onko voinko voitko voisitko moi terve kiitos tarvitsen haluan olen
minä minun meidän hänen poikani tyttäreni äitini isäni vaimoni mieheni tätini setäni lankoni siskoni veljeni
viết dịch giải tóm giúp kiểm làm tạo kể sửa liệt tính soạn lên gợi tại sao thế nào gì đâu xin chào cảm ơn tôi
chị chúng họ mình bạn nhờ hãy
tulis tuliskan terangkan jelaskan bantu bantulah tolong semak periksa cek bandingkan buat buatkan ceritakan berikan
betulkan perbaiki senaraikan kira hitung draf ringkaskan rangkum terjemahkan analisis apa mengapa kenapa bagaimana
macam mana siapa kapan boleh bisa aku kami kawan teman nama terima kasih halo selamat akaun obat
írj írd fordítsd magyarázd foglald összefoglald segíts ellenőrizd hasonlítsd készíts mondd javítsd sorold számold
miért hogyan kik melyik mikor hol szia helló köszönöm kérlek szeretnék véletlenül
napiši prevedi objasni sažmi pomozi provjeri usporedi napravi reci daj ispravi nabroji izračunaj kako zašto što
tko koji kada gdje bok zdravo hvala molim trebam otac majka preporučio
napíš napiš prelož přelož vysvetli vysvětli zhrň shrň pomôž pomoz skontroluj zkontroluj porovnaj porovnej urob
udělej povedz řekni oprav vypočítaj vypočítej prečo proč jak kto kdo čo ktorý který kedy kdy kde ahoj ďakujem
děkuji prosím potrebujem potřebuji môj můj
skriv översätt oversett oversæt förklara forklar sammanfatta oppsummer opsummer hjälp hjelp hjælp kontrollera
kontroller sjekk tjek jämför sammenlign gör lag berätta fortell fortæl rätta lista beräkna regn svar varför
hvorfor hvad vad hva hur hvordan vem hvem vilken vilka vilket hvilken hvilke hvilket när når hvor hej hei takk
tak snälla jag jeg pakken paketet stämmer stemmer underskrevet
scrie tradu explică rezumă ajută verifică compară creează spune corectează enumeră calculează cum cine când unde
bună salut mulțumesc tatăl mama fiul fiica soțul soția
γράψε μετάφρασε εξήγησε βοήθησε έλεγξε σύγκρινε φτιάξε πες δώσε διόρθωσε υπολόγισε γιατί πώς ποιος ποια ποιο
πότε πού γεια καλημέρα ευχαριστώ παρακαλώ χρειάζομαι θέλω εγώ εμείς
çevir açıkla özetle yardım kontrol karşılaştır yap oluştur anlat düzelt listele hesapla neden niye nasıl kim
hangi nerede merhaba selam teşekkürler lütfen benim bizim annem babam oğlum kızım eşim
gumawa isulat isalin ipaliwanag ibuod tulungan tulong suriin ikumpara pacheck sabihin ibigay ayusin ilista
kalkulahin bakit paano sino kailan saan kailangan pwede puwede namin aking salamat kumusta
explícame escribe traduce resume ayúdame revisa compara haz crea dime dame corrige calcula redacta copiado copiada
explica escreve escreva traduz traduza resuma ajuda faz faça cria diz diga corrija redige pede
spiegami scrivi traduci riassumi aiutami controlla confronta crea dimmi dammi correggi calcola fatemi copiato
copiata cosa
escriu tradueix resumeix revisa digues corregeix
explique écris traduis résume vérifie fais crée dis donne corrige calcule rédige
erkläre erklär schreib schreibe übersetze fasse hilf prüfe vergleiche mach erstelle sag gib korrigiere berechne kurz
schrijf vertaal vat controleer vergelijk maak zeg geef corrigeer bereken
напиши переведи объясни перескажи помоги проверь сравни сделай создай скажи дай исправь посчитай почему как кто
какой когда где привет здравствуйте спасибо пожалуйста мне мой моя
переклади поясни підсумуй допоможи перевір порівняй зроби створи виправ порахуй чому як хто який коли де привіт
дякую мій
napisz przetłumacz wyjaśnij streść pomóż sprawdź porównaj zrób stwórz powiedz popraw policz dlaczego jak kto który
kiedy gdzie cześć dziękuję proszę potrzebuję mój moja
लिखो लिखें अनुवाद समझाओ समझाएं सारांश मदद जांचो तुलना बनाओ बताओ क्यों कैसे कौन कब कहाँ नमस्ते धन्यवाद कृपया मेरा मेरी मुझे
লেখো অনুবাদ বোঝাও ব্যাখ্যা সারাংশ সাহায্য যাচাই তুলনা বানাও বলো কেন কীভাবে কোথায় নমস্কার ধন্যবাদ আমার আমাকে আমরা
لکھیں لکھو ترجمہ سمجھائیں وضاحت خلاصہ مدد موازنہ بنائیں بتائیں کیوں کیسے کون کب کہاں شکریہ براہ مہربانی میرا میری مجھے
اكتب ترجم اشرح لخص ساعدني راجع قارن أنشئ صحح احسب لماذا كيف متى أين مرحبا شكرا لي أنا نحن
כתוב תרגם הסבר סכם עזור בדוק השווה צור תגיד תקן חשב איך איזה מתי איפה שלום
เขียน แปล อธิบาย สรุป ช่วย ตรวจ เปรียบเทียบ สร้าง บอก แก้ คำนวณ ทำไม อย่างไร ใคร อะไร เมื่อไร ที่ไหน สวัสดี ขอบคุณ
எழுது விளக்கு சுருக்கம் உதவி சரிபார் ஒப்பிடு சொல் ஏன் எப்படி யார் எது எப்போது எங்கே வணக்கம் நன்றி
రాయి అనువదించు వివరించు సారాంశం సహాయం తనిఖీ పోల్చు చెప్పు ఎందుకు ఎలా ఎవరు ఏది ఎప్పుడు ఎక్కడ నమస్కారం ధన్యవాదాలు
`;

/** And what a person is called before their name: a relative, a party to a
 *  contract, a title cut at its full stop, the greeting of a letter.
 *  "Teściowa, pani Krystyna", "Svigermor Solveig", "Sælger Erik Damgaard",
 *  "Pt. Vestergaard", "MUDr. Stejskalová", "Poštovani gospodine",
 *  "Tisztelt Vörös úr" (realistic5 false alarms, 2026-10-24). */
const BEFORE_A_NAME_WORDS = `
tchyně tchán teściowa teść svigermor svigerfar svigermoren svigerinde svärmor svärfar anoppi appi apu anyu anyós após
tată tatăl mamă mama otec matka majka ojciec matka córka syn żona mąż babcia dziadek babička dědeček
sælger køber sælgeren køberen säljare köpare selger kjøper kandidát kandidat uchazeč myyjä ostaja vendedor comprador
venditore acquirente verkoper koper verkäufer käufer vânzător cumpărător sprzedający kupujący prodávající kupující
pt pat mudr mvdr judr phdr mgr ing bc doc prof dr dra sra srta sr hr fr herrn
poštovani poštovana poštovaní vážený vážená vážení tisztelt kedves stimate stimată stimați αγαπητή αγαπητέ αξιότιμε
αξιότιμη szanowny szanowna szanowni drogi droga шановний шановна уважаемый уважаемая дорогой дорогая
`;

/** Medicines by the names people ask about them: the taggers read a brand
 *  as a person ("ia Sintrom și acum i-au dat Nurofen", "האם מותר אדוויל עם
 *  אקמול"; realistic5, 2026-10-25). The commonest generics and brands, in
 *  Latin letters and as Hebrew, Russian and Greek write them. */
const MEDICINE_WORDS = `
paracetamol acetaminophen ibuprofen aspirin aspirina naproxen diclofenac metamizol metamizole tramadol codeine
amoxicillin amoxicilina augmentin azithromycin ciprofloxacin doxycycline penicillin cephalexin
metformin insulin losartan amlodipine lisinopril ramipril bisoprolol metoprolol atenolol valsartan
atorvastatin simvastatin rosuvastatin warfarin sintrom acenocoumarol xarelto rivaroxaban eliquis apixaban clopidogrel
omeprazole pantoprazole esomeprazole ranitidine levothyroxine euthyrox prednisone prednisolone dexamethasone
salbutamol ventolin cetirizine loratadine sertraline fluoxetine escitalopram amitriptyline gabapentin pregabalin
ozempic semaglutide sildenafil viagra
panadol tylenol advil nurofen brufen voltaren aspirine doliprane dafalgan efferalgan nolotil gelocatil enantyum
buscopan imodium zyrtec claritin nexium concor lipitor crestor glucophage januvia
אקמול ואקמול אדוויל נורופן אופטלגין וולטרן קלקסן
парацетамол ибупрофен нурофен аспирин анальгин цитрамон но-шпа ношпа валидол корвалол
παρακεταμόλη ντεπόν
martefarin syncumart ibalgin waran warfarin marevan sintrom algopyrin xarelto eliquis pradaxa
pot
`;
/* The last two lines from realistic5 (2026-11-02): blood thinners and pain
 * relief by their Croatian, Hungarian, Slovak and Swedish brand names, and
 * the patient's abbreviation a Finnish discharge note opens with, "Pot.
 * Laitinen". Not Norway's "Pas.": "te Pas" is a Dutch surname. */

/** Ordinary words of the scripts without capitals that the taggers took for
 *  names in realistic5 (2026-10-25), with their kind: pronouns and the words
 *  for me and you, a few numbers, roles and relatives, and the English words
 *  these languages write in their own letters (মিটিং, इंजीनियर, మెయిల్). */
const SCRIPT_COMMON_WORDS = `
আমাদের খতিয়ান আমি আমার আমাকে আপনার আপনি তুমি তোমার ওনার ওর তার দুই তিন এক নাম সরকারি মালিক চেক দাও ওপর মিটিং মিটিংয়ের হেডস্যার স্যার
मैं मेरा मेरी मुझे आप आपका आपकी तुम हम मम्मी पापा कोर्ट इंजीनियर मेंबर्स मेंबर मरीज़ मरीज़ा रेफ़रल लेटर टीम मैनेजर
من أنا انا أول ثاني إيميل ايميل سكني سنوي بنتي ولدي مدير الاسم اسم السياسة الطالب التشخيص عايز شيك هالمحادثة
نام شناختی کارڈ موبائل شہر علم طالب ماہر مینیجر پروکیورمنٹ ریفرل لیٹر گیزر آلو نان فائلر
আমি আমার আমাকে আপনার আপনি তুমি তোমার ওনার ওর তার দুই তিন এক নাম সরকারি মালিক চেক দাও ওপর মিটিং মিটিংয়ের হেডস্যার স্যার
प्रिय विंड चाइम मैं मेरा मेरी मुझे आप आपका आपकी तुम हम मम्मी पापा कोर्ट इंजीनियर मेंबर्स मेंबर मरीज़ मरीज़ा रेफ़रल लेटर टीम मैनेजर
من أنا انا أول ثاني إيميل ايميل سكني سنوي بنتي ولدي مدير الاسم اسم
אני אתה את מלא טלפון אפשר הפגישה מייל שם
நான் நீ நீங்கள் அக்கா அண்ணா திரு நடிகர் டெம்ப்ளேட் பரிவர்த்தனை
పేరు నంబర్ ఆల్రెడీ షేర్ ప్రియమైన నేను నువ్వు మీరు స్టాండర్డ్ బర్త్ మెయిల్ నాన్నగారు నాన్న అమ్మ తాతయ్య యజమాని స్టార్ట్ వాషింగ్ మెషిన్
ลูกค้า ผม ฉัน คุณ
врач полис пациент
φιλιά γειτονας γείτονας
`;

/** What people call a relative, a stranger or somebody they serve, in place
 *  of a name or in front of one: "Notfallkontakt Oma Brigitte", "Encik
 *  Rahman", "Lolo ko", "ازيك يا باشا". The tagger took the word for the
 *  person (realistic5, 2026-10-26); the name after it is still found. */
const KIN_AND_TITLE_WORDS = `
oma opa omi opi mutti vati herrn frau herr
ama ina lolo tita tito kuya ate inay itay
opah atok nenek bapa ibu pak bu encik cik tun datuk dato datin puan tuan
khun
bà ông cụ
babcia dziadek mama tata tato mamo babička dědeček dedko babka
anneanne babaanne dede teyze amca hala dayı yeğenim arkadaşım abla abi
бабуся бабусі бабушка дедушка свекруха свекровь мама тато папа
امی ابو ابا بابا ماما باشا شیخ خالہ
여사 할머니 할아버지
kamarátka kamarát kamarádka kamarád
pacient pacjent pacijent pesakit patiënt pasien müşteri hasta
menteri perdana
veljenpoikani veljentyttäreni
`;

/** Ordinary words that open a sentence, sign off a message or label a form,
 *  in the languages whose capitalised words the tagger read as names in
 *  realistic5 (2026-10-26): "Soita 040 …", "Terveisin", "Prezados",
 *  "Siparişiniz kargoya verilmiştir", "Dzień dobry", "Üdv". */
const SENTENCE_WORDS = `
soita terveisin allekirjoittaa ilmoittautumiset voidaanko toistaiseksi olen asentaja projektipäällikkö taloyhtiön ajetaan
prezados prezada prezado olá
siparişiniz adım kimlik davacı davalı yöneticisi
dzień robić
dobrý posielam zdvorilejšie
küldöm üdv köszönjük adóazonosító
antwoord veranderd
salam mesyuarat dikirim jumat
semnez contul până
j'ai écrire condoléances
ime dobijem
tillträde heltid gipsad
andiamo matricola
versichertennr bürgergeld
affidavit sarado
alicatado
עדכון מותר
عدالت فارم کارڈ فائلر
prüf přihlášku siistitkö työtodistus interjút kontroll lagu
eki çar
tỉnh số sđt cần chuyển khác khiếu
`;

/** German nouns by an ending no name has: Freiheit, Möglichkeit,
 *  Gesellschaft, Qualität, Tourismus. -erin, -istin and -tion were
 *  measured too and left out, as names carry them (Kristin, Guerin, Eltion). */
const GERMAN_NOUN_ENDING = /^\p{Lu}\p{Ll}+(?:heit|keit|schaft|tät|ismus)$/u;

// Less any that is also somebody's given name — "Mia" is Italian for "my",
// "Ella" Spanish for "she", "Anders" Dutch for "otherwise" — so the list can
// only ever remove words, never a name.
/* Words the taggers and the cues took for people on realistic5's practice
   half (2026-11-07): a verb that opens a sentence, a word for a customer or an
   admin, a thing with a capital. "Se" opens sentences; all are
   lower case here and any given name is taken back out below. */
const STILL_TAKEN_WORDS = `
olet piirin ranteen kami olimpik se nøgle m'han história hội pixel
אפשר הפגישה תתקשר המנגל קובץ
కస్టమర్ సమ్మరీ సమ్మరీని ลูกค้า แอดมิน โทร 여사 نادرا
`;

const SET: ReadonlySet<string> = new Set(`${STILL_TAKEN_WORDS} ${WORDS} ${DOCUMENT_WORDS} ${QUESTION_WORDS} ${REQUEST_WORDS} ${BEFORE_A_NAME_WORDS} ${MEDICINE_WORDS} ${SCRIPT_COMMON_WORDS} ${KIN_AND_TITLE_WORDS} ${SENTENCE_WORDS}`.split(/\s+/).filter((w) => w && !GIVEN_NAMES.has(w)));

/** A word of another language's ordinary vocabulary, or a phrase made only of
 *  them ("Vielen Dank", "Sehr geehrte", "mijn vrouw"). */
export function isForeignCommonWords(name: string): boolean {
  const bare = name.replace(/[.,!?:;]+$/, "");
  const words = bare.toLowerCase().split(/\s+/).filter(Boolean);
  if (words.length === 1 && GERMAN_NOUN_ENDING.test(bare) && !GIVEN_NAMES.has(words[0])) return true;
  return words.length > 0 && words.every((w) => SET.has(w));
}

/**
 * A greeting that is also somebody's name, used as the greeting: "Cher
 * Shqipton," is "Dear Shqipton", not the singer. The word list keeps "Cher",
 * "Cara" and "Beste" because people are called that; so one is refused only
 * where every time the text writes it, another word with a capital (or in a
 * script without capitals) comes straight after it (namesMultilingual
 * practice half, 2026-10-31: "cher" wrongly taken five times). And Croatian
 * and Romanian "Draga Martina", "Draga Ioana" (realistic5, 2026-11-02).
 */
const GREETINGS_THAT_ARE_NAMES = new Set(["cher", "chère", "chere", "cara", "caro", "beste", "lieve", "liebe", "lieber", "querida", "querido", "estimada", "estimado", "prezada", "prezado", "dear", "draga", "dragi", "dragă"]);
export function isGreetingHere(name: string, text: string): boolean {
  const bare = name.trim();
  if (/\s/.test(bare) || !GREETINGS_THAT_ARE_NAMES.has(bare.toLowerCase())) return false;
  const re = new RegExp(`(?<![\\p{L}])${bare.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?![\\p{L}])`, "gu");
  const after = [...text.matchAll(re)].map((m) => text.slice((m.index ?? 0) + bare.length, (m.index ?? 0) + bare.length + 3));
  return after.length > 0 && after.every((a) => /^[ \t]+(?:\p{Lu}|[^\p{Script=Latin}\p{N}\s\p{P}])/u.test(a));
}

/**
 * A German compound written with a hyphen whose last part is an ordinary
 * noun: "Mosaik-Kurs", "Führerschein-Nummer", "Mode-Laufsteg", "Dent-Karten".
 * A double surname ends in a surname (Müller-Lüdenscheidt), not in one of
 * these (namesMultilingual practice half, 2026-10-31).
 */
const COMPOUND_NOUN_TAIL = /-(?:kurs|kurse|nummer|route|reiseroute|karte|karten|laufsteg|gruppe|workshop|projekt|programm|plan|liste|formular|adresse|termin|zentrum|verein|abteilung|service|system|methode|technik|muster|stil|tanz|markt|daten|bericht|vertrag|antrag|konto|ausweis|schein|code|team|kunde|kunden|preis|zeit|tag|woche|pflanzen|etiketten|gedichte|bord|board|sammlung|ideen|tipps|regeln)$/i;
export function isNounCompound(name: string): boolean {
  return !/\s/.test(name.trim()) && COMPOUND_NOUN_TAIL.test(name.trim());
}

/** The name after a greeting the tagger read as part of it: "Hallo
 *  Makeswaran" -> "Makeswaran". The same name if nothing leads it. */
export function withoutGreeting(name: string): string {
  const words = name.split(/\s+/);
  let i = 0;
  while (i < words.length - 1 && SET.has(words[i].toLowerCase().replace(/[.,!]+$/, ""))) i += 1;
  return words.slice(i).join(" ");
}

/** English titles, with or without their full stop. */
const TITLES = new Set([
  "mr", "mrs", "ms", "mx", "miss", "mister", "dr", "prof", "sir", "madam", "madame",
  // Abbreviated titles in Spanish, French, German, Italian and Dutch. Not
  // "Don", which is also a first name.
  "sr", "sra", "srta", "dra", "mme", "mlle", "herr", "herrn", "frau", "sig", "sigra", "dott", "avv", "dhr", "mevr",
]);
/** Japanese honorifics written in Latin letters. "Chan" and "San" are also
 *  names in Latin script (Jackie Chan, San Martín), so they are taken off
 *  only in front of a name written in kana or Chinese characters, where they
 *  cannot be part of it. */
const ROMAJI_HONORIFICS = new Set(["chan", "san", "sama", "kun", "sensei"]);
const CJK = /[\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}]/u;

/** The name after a title the tagger read as part of it: "Mr. Zilke Eades"
 *  -> "Zilke Eades", "chan ゆきか 岩崎" -> "ゆきか 岩崎", "mr. 忠羿" -> "忠羿".
 *  The title stays in the text, readable; only the name is hidden. A title
 *  alone, with nothing after it, is returned as it was, for the filters
 *  after this to judge. */
/** A title on its own, with or without its dot: "Sra.", "Dr", "Herr". The
 *  model sometimes returns one by itself when it reads "Estimada Sra. Ortega";
 *  withoutTitle leaves a lone word alone, so this is checked after it. */
export function isBareTitle(name: string): boolean {
  // Or titles only: "Herrn Dr" out of "an Herrn Dr. Leopold Wenzel"
  // (realistic5, 2026-11-08).
  return name.split(/\s+/).every((w) => TITLES.has(w.toLowerCase().replace(/\.$/, "")));
}

export function withoutTitle(name: string): string {
  const words = name.split(/\s+/);
  let i = 0;
  while (i < words.length - 1) {
    const w = words[i].toLowerCase().replace(/\.$/, "");
    const rest = words.slice(i + 1).join(" ");
    if (TITLES.has(w) || (ROMAJI_HONORIFICS.has(w) && CJK.test(rest))) i += 1;
    else break;
  }
  return words.slice(i).join(" ");
}
