/**
 * Given names, for telling a user name made of a name ("Gaston84",
 * "Jacques.Schneider") from one made of a product or a term ("Vector3",
 * "Base64", "Crypto.Cipher").
 *
 * Every name in the US top thousand for either sex in any year from 1900 to
 * 2008: the Social Security Administration's baby-name counts (public
 * domain), as compiled in hadley/data-baby-names. 6,032 names, lower case.
 * It is a US list and misses names that are rare there; a miss only means a
 * handle with no cue is not taken, which is how it was before the list.
 */
export const GIVEN_NAMES: ReadonlySet<string> = new Set(`
aaden aaliyah aarav aaron abagail abbey abbie abbigail abby abdiel abdul abdullah abe abel abelardo
abigail abigale abigayle abner abraham abram abril ace acie ada adah adalberto adaline adalyn
adalynn adam adamaris adan adda addie addison addisyn addyson adela adelaide adelbert adele adelia
adelina adeline adell adella adelle adelyn aden adilene adin adison aditya adline admiral adolf
adolfo adolph adolphus adonis adrain adria adrian adriana adriane adrianna adrianne adriel adrien
adriene adrienne adron adyson aedan afton agatha aggie agnes agustin ahmad ahmed aida aidan aiden
aidyn aileen ailene aili aimee ainsley aisha aiyana aja akeelah akeem akira al alaina alan alana
alani alanna alannah alayna alba albert alberta albertha albertina albertine alberto albin albina
alcide alda alden aldo aldona aleah alease alec alecia aleen aleena alejandra alejandro alek alena
alene alesha alesia alessandra alessandro aleta aletha alethea alex alexa alexande alexander
alexandr alexandra alexandre alexandrea alexandria alexandro alexia alexis alexus alexys alexzander
alf alfie alfonse alfonso alfonzo alford alfred alfreda alfredo algie ali alia aliana alice alicia
alida alijah alina aline alisa alisha alison alissa alisson alivia aliya aliyah aliza alize alla
allan allean allen allene allie alline allison allisson ally allyn allyson allyssa alma almeda almer
almeta almira almon alois aloma alondra alonso alonza alonzo aloysius alpha alpheus alphonse
alphonso alphonsus alta altha althea alton alva alvah alvan alvaro alvena alvera alverda alverta
alvie alvin alvina alvira alvis alyce alycia alys alysa alyse alysha alysia alyson alyssa alyssia
alyvia amado amalia amanda amani amara amare amari amarion amaris amaya amber amberly ambrose amelia
amelie america americo amerigo ami amiah amie amin amina amir amira amirah amit amiya amiyah ammie
ammon amon amos amparo amy amya ana anabel anabella anabelle anahi anais anastacio anastasia anaya
ancil anders anderson andon andra andrae andre andrea andreas andres andrew andria andy anfernee
angel angela angeles angelia angelic angelica angelina angeline angelique angelita angella angelo
angie angus anibal anika anissa anita anitra aniya aniyah anjali anjanette anjelica ann anna annabel
annabell annabella annabelle annalise annamae annamarie anne anneliese annemarie anner annetta
annette annie annika annis annmarie anona ansel ansley anson anthoney anthony antione antionette
antoine antoinette anton antone antonetta antonette antonia antonina antonio antony antwain antwan
antwon anwar anya april ara arabella araceli aracely arbie arch archibald archie ardath ardelia
ardell ardella ardelle arden ardeth ardis ardith ardyce areli arely aretha ari aria ariana ariane
arianna aric arie ariel ariella arielle arietta arizona arjun arla arlan arland arleen arlen arlena
arlene arleth arletta arley arlie arlin arline arlington arlis arlo arly arlyn arlyne arman armand
armando armani armida armin armond arnav arne arnetta arnie arno arnold arnoldo arnulfo aron arrie
arron arsenio art arther arthur artie artis arturo arvel arvid arvil arvilla arvin arvo aryan aryana
aryanna asa asbury asha ashanti ashby ashely asher ashlea ashlee ashleigh ashley ashli ashlie ashly
ashlyn ashlynn ashton ashtyn asia aspen assunta astrid atha athena atticus attilio aubree aubrey
aubrie audie audley audra audrey audriana audrianna audrina audry august augusta augustin augustina
augustine augustus aura aurelia aurelio aurora aurore austen austin auston austyn auther author
authur autry autumn ava avah averi averie avery avis axel ayaan ayana ayanna aydan ayden aydin
ayesha ayla aylin azalee azaria azul babette baby babyboy bailee bailey ballard bama bambi barb
barbara barbie barbra barnett barney barnie baron barrett barrie barron barry bart bartholomew
bartley barton bascom basil baxter baylee baylie bea beadie beatrice beatriz beau beaulah bebe
beckett beckham beckie becky bedford bee beecher belen belia belinda bell bella belle belton belva
ben benard benedict benita benito benjaman benjamen benjamin benjamine benji benjiman bennett bennie
benny benson bentley benton berdie berenice berlin bernadette bernadine bernard bernardine bernardo
berneice bernetta bernhard bernice bernie berniece bernita berry bert berta bertha bertie berton
bertram bertrand beryl bess besse bessie beth bethann bethany bethel bethzy betsey betsy bette
bettie bettina betty bettye bettyjane bettylou beula beulah bev beverlee beverley beverly beyonce
bianca bilal bill billie billy billye bina birdie birtha birtie bishop bjorn blaine blair blaise
blake blanca blanch blanche blanchie blane blas blaze blossom bo bob bobbi bobbie bobby bobbye bode
bonita bonnie bonny booker boris boss boston boyce boyd brad braden bradford bradley bradly brady
bradyn braeden braedon braelyn braiden brain brandan brande brandee branden brandi brandie brandin
brandon brandt brandy brandyn brannon branson brant brantley braulio braxton brayan brayden braydon
braylen braylon brea breana breann breanna breanne bree brenda brendan brenden brendon brenna
brennan brennen brennon brent brenton breonna bret brett bria brian briana brianda brianna brianne
brice bridger bridget bridgett bridgette brielle brien brigette brigid brigitte briley brinda brion
brionna brisa britany britney britni britny britt britta brittaney brittani brittanie brittany
brittnay brittnee brittney brittni brittnie brittny britton brock broderick brodie brody brogan
bronson brook brooke brooklyn brooklynn brooks brown bruce bruno bryan bryana bryanna bryant bryce
brycen brylee bryn brynlee brynn bryon bryson bryton buck bud budd buddie buddy buel buelah buena
buffy buford bula bulah buna burdette buren burke burl burley burnell burnett burnice burrell burt
burton buster butch butler byrd byron cade caden cadence cael caesar caiden cailyn cain caitlin
caitlyn caitlynn cal caldonia cale caleb caleigh cali calista callie callum calvin camden cameron
cami camila camilla camille camisha cammie campbell camren camron camryn candace candi candice
candida candis candy candyce cannon canyon cap capitola caprice cara caren carey cari carie carin
carina carisa carissa carl carla carlee carleen carleigh carlene carleton carley carli carlie carlo
carlos carlotta carlton carly carlyle carlyn carma carmel carmela carmelita carmella carmelo carmen
carmine carnell carol carolann carole carolee carolina caroline carolyn carolyne carolynn caron
carri carrie carrol carroll carry carsen carson carter cary caryl caryn casandra case casey cash
casie casimer casimir cason casper cass cassandra cassidy cassie cassius cassondra catalina
catharine catherine cathey cathi cathie cathleen cathrine cathryn cathy catina catrina cayden cayla
caylee ceasar cecelia cecil cecile cecilia cecily cedric cedrick ceil celena celesta celeste
celestine celia celina celine ceola cephus cesar chace chad chadd chadrick chadwick chaim chaka
chalmer chalmers champ chana chance chanda chandler chandra chanel chanelle channing chantal chante
chantel chantelle charissa charisse charity charla charlee charleen charlene charles charley charlie
charline charlize charlotte charlsie charlton charmaine charolette chas chase chasity chastity
chauncey chaya chaz che chelsea chelsey chelsi chelsie chelsy cher cherelle cheri cherie cherilyn
cherise cherish cherrelle cherri cherrie cherry cherryl cheryl cheryle cheryll chesley chester chet
cheyanne cheyenne chimere chin china chip chiquita chloe chris chrissy christ christa christal
christeen christel christen christena christene christi christian christiana christie christin
christina christine christion christop christoper christopher christy chrystal chuck chyna chynna
ciara ciarra cicely cicero cielo ciera cierra ciji cinda cindi cindy cinnamon cinthia citlali
citlalli clair claire clara clarabelle clarance clare clarence claribel clarice clarine clarisa
clarissa clark clarke clarnce classie claud claude claudette claudia claudie claudine claudio clay
clayton clearence cleda clell clella clem clemence clemens clement clementina clementine clemmie
cleo cleola cleon cleone cleora cleta cletus cleve cleveland clide cliff clifford clifton clint
clinton clive cloe clora clovis cloyd clyde clydie coby codey codi codie cody coen cohen colby cole
coleen coleman coleton coletta colette coley colie colin colleen collette collie collin collins
collis colonel colt colten colter colton columbus concepcion concetta concha conley conner connie
connor conor conrad constance constantine consuela consuelo contina conway coolidge cooper cora
coraima coral coralie corbin corda cordaro cordelia cordell cordero cordia cordie corean corene
coretta corey cori corie corina corine corinna corinne corliss cornel cornelia cornelious cornelius
cornell corrie corrina corrine corry cortez cortney corwin cory cosmo coty council courtland
courtney coy craig crawford creed creola cris crissy crista cristal cristen cristi cristian cristin
cristina cristine cristobal cristofer cristopher cristy cruz crysta crystal cullen curley curt
curtis curtiss cydney cyndi cynthia cyril cyrus dafne dagmar dagny dahlia daija daijah daisey daisha
daisy daja dakoda dakota dakotah dale dalia dallas dallin dalton dalvin damarcus damari damarion
damaris dameon damian damien damion damon damond dan dana danae dandre dane daneen danelle danette
dangelo dani dania danial danica daniel daniela daniele daniella danielle danika danita dann danna
dannie danniel dannielle danny dante danyel danyell danyelle daphne daquan dara darby darci darcie
darcy darell daren daria darian dariana darien darin dario darion darius darl darla darleen darlene
darline darlyne darnell darold daron darrel darrell darren darrian darrick darrien darrin darrion
darrius darron darry darryl darryle darryll darryn darvin darwin darwyn daryl daryle daryn dashawn
dasia daulton daunte davante dave davey davian david davie davin davina davion davis davon davonta
davonte davy dawn dawna dawne dawson dax daxton dayami dayana dayanara dayle dayna dayne dayton
deacon dean deana deandra deandre deane deangelo deann deanna deanne deante deasia deb debbi debbie
debbra debby debera debi debora deborah deborrah debra debrah debroah declan dedra dedric dedrick
dee deeann deedee deegan deena deidra deidre deion deirdre deja dejah dejon dejuan del delaney
delano delbert delcie delfina delia delilah delinda delisa dell della dellar dellie delma delmar
delmas delmer delmus delois delora delores deloris delos delpha delphia delphin delphine delsie
delta delton delvin delwin demarco demarcus demario demarion demetra demetri demetria demetric
demetrios demetrius demi demian demond demonte dempsey dena deneen denese denice denine denis denise
denisha denisse denita dennie dennis denny denton denver denzel denzell denzil deon deondre deonta
deontae deonte dequan derald dereck derek dereon deric derick derik derl deron derrek derrell
derrick derwin deryl desean deshaun deshawn desi desirae desiree desmond dessa dessie destany destin
destinee destiney destini destiny destry devan devante devaughn deven devin devon devonta devontae
devonte devyn deward dewayne dewey dewitt dexter deyanira diallo diamond dian diana diandra diane
diann dianna dianne dicie dick dickie diego dijon dillan dillard dillie dillion dillon dimitri
dimitrios dimple dina dinah dino dion dione dionne dionte dirk dixie diya djuana djuna doc docia
dock doctor dola doll dollie dolly dolores doloris dolphus domenic domenica domenick domenico
dominga domingo dominic dominick dominik dominique dominque domonique don dona donal donald donato
donavan donavon dondre donell donie donita donn donna donnell donnie donny donovan donta dontae
donte dora dorathy dorcas doreen dorene doretha doretta dori dorian dorinda dorine doris dorla
dorman dorotha dorothea dorothy dorris dorsey dortha dorthea dorthey dorthy doshia doshie dottie
dotty doug douglas douglass dovie dow doyle drake draven drema drew drucilla drusilla duane duard
dudley duke dulce dulcie duncan durell durrell durward durwood dustan dustin dusty duwayne dwain
dwaine dwan dwane dwayne dwight dwyane dyan dylan dyllan dylon ean earl earle earlean earlene earlie
earline early earnest earnestine eartha easter easton eathel ebba eboni ebony echo ed eda edd eddie
eddy eden edgar edgardo edie edison edith edmon edmond edmonia edmund edna edra edrie edris edsel
edson eduardo edward edwardo edwin edwina edyth edythe effie efrain efrem efren egbert eileen einar
eino ela elaina elaine elana elayne elba elbert elberta elda elden elder eldon eldora eldred
eldridge eleanor eleanora eleanore elease electa elena eleni elenor elenora elenore elex elfrieda
elgin eli elian eliana elianna elias elida elie eliezer eliga eligah elige elijah elinor elinore
eliot elisa elisabeth elise eliseo elisha elissa eliza elizabet elizabeth elizebeth ella ellamae
ellar elle ellen ellery elliana ellie elliot elliott ellis ellison ellsworth ellwood ellyn elma
elmer elmira elmo elmore elna elnora elois eloisa eloise elouise eloy elroy elsa elsie elta elton
elva elvera elvia elvie elvin elvina elvira elvis elwanda elwin elwood elwyn ely elyse elyssa elza
elzie emanuel emelia emeline emely emerald emerson emery emil emile emilee emilia emiliano emilie
emilio emily emma emmalee emmaline emmanuel emmer emmet emmett emmie emmit emmitt emmy emogene emory
ena enid ennis enoch enola enos enrico enrique enriqueta enzo eola ephraim ephriam era erasmo eric
erica erich erick ericka erie erik erika erin eris erland erlene erlinda erline erling erma erna
ernest ernestina ernestine ernesto ernie ernst errol ervin erwin erykah eryn esau esco esker
esmeralda esperanza essence essie esta esteban estefani estefania estefany estel estela estell
estella estelle ester estevan esther estill eston estrella etha ethan ethel ethelene ethelyn ethen
ether ethyl ethyle etna etta ettie eudora eugene eugenia eugenie eugenio eula eulah eulalia euna
eunice euphemia eura eusebio eva evaline evalyn evan evangelina evangeline evans eve evelena evelin
evelina eveline evelyn evelyne ever everet everett everette evert evertt evette evia evie evita evon
evonne ewald ewell ewing exie ezekiel ezell ezequiel ezra ezzard fabian fabiola fae fairy faith
fallon falon fannie fanny farah faron farrah farrell farris fate fatima faustino fawn fay faye
fayette federico felecia felice felicia felicitas felicity felipa felipe felisha felix felton fenton
ferdinand fern fernand fernanda fernando ferne ferrell ferris fidel fidencio filomena finis finley
finn finnegan fiona fisher fitzgerald fitzhugh fleming fleta fletcher flint flo flonnie flor flora
florance florence florene florentino floretta florian florida florie florine florrie flossie floy
floyd foch fonda ford forest forrest foster foy fran frances francesca francesco francine francis
francisca francisco franco frank frankie franklin franklyn franz frazier fred freda freddie freddy
frederic frederica frederick fredie fredric fredrick fredy freeda freeman freida french frida frieda
fritz frona fronie fulton fumiko furman gabe gabriel gabriela gabriella gabrielle gael gaetano gage
gaige gail gale galen galilea gannon gardner garett garey garfield garland garner garnet garnett
garold garret garrett garrick garrison garry garth garvin gary gasper gaston gauge gaven gavin gavyn
gay gaye gayla gayle gaylen gaylene gaylon gaylord gaynell gearld gearldine geary gemma gena genaro
gene general genesis geneva genevieve genie gennaro gennie geno geo geoff geoffrey george georgeann
georgene georgetta georgette georgia georgiana georgiann georgianna georgie georgina georgine
geovanni gerald geraldine geraldo geralyn gerard gerardo gerda gerhard gerhardt geri germaine german
gerold gerri gerrit gerry gertha gertie gertrude gia giada giana giancarlo gianna gianni gideon
gidget gifford gigi gil gilbert gilberto gilda giles gillian gilmer gilmore gina ginger ginny gino
giovani giovanna giovanni giovanny girtha gisele giselle gisselle giuliana giuseppe gladis gladyce
gladys glen glenda glendon glendora glenn glenna glennie glennis glenwood glinda gloria glover
glynda glynis glynn godfrey goebel golda golden goldia goldie gonzalo gorden gordon gorge gottlieb
grace gracelyn gracie graciela grady graham grant granville gray grayce graydon grayling grayson
grecia green greg gregg greggory gregoria gregorio gregory greta gretchen greyson griffin grisel
griselda grover guadalupe guido guillermo gunnar gunner gurney gus guss gussie gust gusta gustaf
gustav gustave gustavo guy gwen gwenda gwendolyn gwyn gwyneth hadassah haden hadley haiden hailee
hailey hailie hakeem hakim hal halbert haleigh haley hali halie hall halle halley hallie hamilton
hamp hampton hamza hana hank hanna hannah hans hansel harden hardie hardin harding hardy harlan
harland harlen harlene harley harlie harlon harlow harm harmon harmony harold harper harrell harriet
harriett harriette harris harrison harrold harry hartley haruko harve harvey harvie harvy hasan
hasel haskell hassan hassie hattie haven hayden hayes haylee hayleigh hayley haylie hayward haywood
hazel hazen hazle heath heather heaven heber hector hedwig hedy heidi heidy helaine helen helena
helene helga hellen helmer helyn henderson henery henretta henri henrietta henriette henry herb
herbert heriberto herlinda herman hermina hermine herminia hermon hernan herschel hershel hershell
hertha hessie hester hettie heyward hezekiah hideo hilario hilary hilbert hilda hildegard hildegarde
hildred hildur hill hillard hillary hilliard hilma hilton hiram hiroshi hjalmer hobart hobert hobson
hoke holden holland holli hollie hollis holly holmes homer hoover hope horace horacio hortencia
hortense hortensia hosea hosie houston howard howell hoy hoyt hubbard hubert hudson huey hugh hughes
hughie hugo hulda huldah humberto hung hunter hurbert hurley huston huy hyman hymen ian ibrahim icie
icy ida idamae idell idella iesha ieshia ignacio ignatius ike ila ilah ilda ilene iliana illa illya
ilona ima imani imanol imelda immanuel imogene ina india inell ines inez infant inga ingeborg inger
ingrid iola iona ione ira ireland irene iridian irine iris irma irvin irvine irving irwin isa isaac
isaak isabel isabela isabell isabella isabelle isadora isadore isai isaiah isaias isamar ishaan
isham ishmael isiah isidore isidro isis isla ismael isobel isom israel isreal issac itzel iva ivah
ivan ivana iver ivette ivey ivonne ivor ivory ivy iyana iyanna izabella izabelle izaiah izayah
izetta izola izora jabari jabbar jacalyn jace jacey jack jackeline jacki jackie jacklyn jackson
jacky jaclyn jacob jacoby jacque jacquelin jacqueline jacquelyn jacquelynn jacques jacquez jacquline
jacqulyn jada jade jaden jadiel jadon jadyn jaeda jaeden jaelyn jaelynn jagger jaheem jaheim jahiem
jahir jaida jaiden jaidyn jailene jailyn jaime jaimee jaimie jair jairo jajuan jakayla jake jakob
jakobe jaleel jaleesa jalen jalisa jalissa jaliyah jalon jalyn jalynn jamaal jamal jamar jamarcus
jamari jamarion jame jameel jamel james jameson jamey jami jamie jamil jamila jamin jamir jamison
jamiya jammie jamya jan jana janae janay jane janeen janel janell janelle janene janessa janet
janette janey janiah janice janie janine janis janiya janiyah jann janna jannette jannie january
janyce jaquan jaquelin jaqueline jaquez jarad jared jaren jaret jarett jarod jaron jarrad jarred
jarrell jarret jarrett jarrod jarvis jase jasen jasiah jaslene jaslyn jasmin jasmine jasmyn jasmyne
jason jasper jaunita javen javier javion javon javonte jax jaxon jaxson jay jayce jaycee jaycie
jayda jaydan jayde jayden jaydin jaydon jaye jayla jaylah jaylan jaylee jayleen jaylen jaylene
jaylin jaylon jaylyn jaylynn jayme jaymes jayne jayson jayvion jayvon jazlene jazlyn jazlynn jazmin
jazmine jazmyn jazmyne jean jeana jeane jeanetta jeanette jeanie jeanine jeanmarie jeanna jeanne
jeannette jeannie jeannine jeb jed jedediah jedidiah jeff jefferey jefferson jeffery jeffie jeffrey
jeffry jelani jemal jena jenelle jenifer jenilee jenna jennette jenni jennie jennifer jenniffer
jennings jenny jensen jerad jerald jeraldine jeramiah jeramie jeramy jere jered jerel jereme jeremey
jeremiah jeremie jeremy jeri jerica jerilyn jerilynn jerimiah jerimy jermain jermaine jermey jerod
jerold jerome jeromy jerrad jerrel jerrell jerri jerrica jerrie jerrilyn jerrod jerrold jerry jeryl
jesenia jesica jess jesse jessenia jessi jessica jessie jessika jessy jesus jethro jett jettie jevon
jewel jewell jiles jill jillian jim jimena jimmie jimmy jo joan joana joanie joann joanna joanne
joaquin jocelyn jocelyne jocelynn jodi jodie jody joe joel joell joella joelle joellen joesph joetta
joette joey johan johana johanna johathan john johnathan johnathon johney johnie johnna johnnie
johnny johnpaul johnson johny joi joleen jolene jolette jolie joline jon jonah jonas jonatan
jonathan jonathon jonell jones joni jonna jonnie jordan jorden jordi jordin jordon jordy jordyn
joretta jorge jorja jory jose josef josefa josefina joselin joseline joseluis joselyn joseph
josephine josette josh joshua joshuah josiah josie josiephine joslyn jossie josue journey jovan
jovani jovanni jovanny jovany jovita joy joyce joycelyn joye juan juana juanita judah judd jude
judge judi judie judith judson judy judyth jule jules juli julia julian juliana juliann julianna
julianne julie julien juliet juliette julio julious julisa julissa julius june junior junious junius
justen justice justin justina justine juston justus justyn juwan kaaren kacey kaci kacie kacy kade
kadeem kaden kadence kadijah kadin kadyn kaeden kael kaela kaelyn kahlil kai kaia kaiden kaila
kailee kailey kailyn kaitlin kaitlyn kaitlynn kaiya kala kale kaleb kaleena kaleigh kalen kalene
kaley kali kalie kaliyah kallie kalvin kalyn kamari kamden kameron kami kamila kamilah kamora kamren
kamron kamryn kandace kandi kandice kandy kane kanesha kanisha kanye kara karan kareem kareen karel
karen kari karie karim karin karina karis karissa karl karla karlee karlene karley karli karlie
karly karma karol karolyn karon karren karri karrie karson karsyn karter karyl karyme karyn kasandra
kasen kasey kash kasie kason kassandra kassidy kassie katarina kate katelin katelyn katelynn
katerina kathaleen katharine katherin katherine kathern katheryn kathey kathi kathie kathleen
kathlene kathlyn kathrine kathryn kathryne kathy kathyrn kati katia katie katina katlin katlyn
katlynn katrina kattie katy kavon kay kaya kaycee kayden kaydence kaye kayla kaylah kaylan kaylee
kayleigh kaylen kaylene kayley kayli kaylie kaylin kaylyn kaylynn kazuko kazuo keagan keandre keanna
keanu keara keaton kecia keegan keeley keely keena keenan keenen keesha kegan keifer keila keion
keira keisha keith kelan kelby kelcie keli kelis kellan kellee kellen kelley kelli kellie kelly
kelsea kelsey kelsi kelsie kelton kelvin kem ken kenan kendal kendall kendell kendra kendrick kenia
kenisha kenji kenley kenna kennard kennedi kennedy kenneth kenney kennith kennth kenny kent kenton
kenya kenyatta kenyon kenzie keon keri kermit kerri kerrie kerry kerwin kesha keshaun keshawn keshia
kevan keven kevin kevon keyla keyon keyshawn khadijah khalid khalil khalilah khari khiry khloe kia
kian kiana kianna kiara kiarra kiefer kiel kiera kieran kierra kiersten kieth kiley killian kim
kimball kimber kimberely kimberlee kimberley kimberli kimberlie kimberly kimora kindra king kingston
kinley kinsey kinsley kinte kip kipp kira kirby kirk kirsten kirstie kirstin kirt kisha kit kittie
kitty kiya kiyoko kiyoshi kizzie kizzy kobe koby koda kody koen kolby kole kolten kolton konner
konnor korbin kordell korey kori kortney kory kourtney kraig kris krish krissy krista kristal
kristan kristen kristi kristian kristie kristin kristina kristine kristofer kristoffer kristopher
kristy kristyn krysta krystal krysten krystin krystina krystle kunta kurt kurtis kwame kya kyan
kyara kyla kylah kylan kyle kylee kyleigh kylene kyler kylie kymani kyra kyree kyrie kyson lacey
laci lacie lacy ladarius laddie ladonna lady lafayette lahoma laila lailah lainey laisha lakeisha
laken lakendra lakesha lakeshia lakisha lala lamar lamarcus lambert lamont lamonte lana lance landan
landen landin landon landyn lane lanette laney lani lanita lannie lanny laquan laquita lara larae
laraine larissa larkin laron larry lars larue lary lashanda lashawn lashonda lashunda lasonya lassie
latanya latarsha latasha latesha latifah latisha latonia latonya latoria latosha latoya latoyia
latrell latrice latricia latrina launa laura laurance laureen laurel lauren laurence laurene
lauretta laurette lauri laurie laurine lauryn lavada lavar lavelle lavera lavern laverna laverne
lavina lavinia lavon lavona lavonda lavonne lawanda lawerence lawrance lawrence lawson lawton lawyer
layla laylah layne layton lazaro lea leah leamon leana leander leandra leandro leann leanna leanne
leatha leatrice leda lee leeann leeroy leesa leia leif leigh leighton leila leilani leisa leisha
leitha lela lelah leland lelar lelia lem lemmie lemon lempi lemuel len lena lenard lenna lennie
lennon lenny lenon lenora lenord lenore lenwood leo leola leoma leon leona leonard leonardo leone
leonel leonia leonidas leonie leonor leonora leonore leontine leopold leopoldo leora leota lera
leroy les lesa lesia leslee lesley lesli leslie lesly less lessie lester leta letha leticia letitia
lettie letty leva levar levern levi levie levon levy lew lewis lex lexi lexie lexis lexus leyla lia
liam liana liane libbie libby liberty lida liddie lidia lige lila lilah lilia lilian liliana
lilianna lilie lilla lillian lilliana lillianna lillie lilly lily lilyan lilyana lina lincoln linda
lindbergh lindell linden lindsay lindsey lindy linette linnea linnie linsey linton linus linwood
lionel lisa lisandro lisbeth lise lisette lisha lissa lissette lissie lita littie little litzy livia
liz liza lizabeth lizbeth lizeth lizette lizzie llewellyn lloyd lockie logan lois lola lolita lollie
loma lon lona london londyn loney long loni lonie lonna lonnie lonny lonzo lora loraine loran
lorayne lorean loree loreen lorelai lorelei loren lorena lorene lorenz lorenza lorenzo loretta
loretto lori loria loriann lorie lorin lorinda lorine loris lorna lorne lorraine lorrayne lorri
lorrie lossie lota lottie lou louann louella louetta louie louis louisa louise lourdes louvenia love
lovell lovie lovina lowell loy loyal loyce loyd lu luana luann luanne luberta luc luca lucas lucero
lucia lucian luciana luciano lucie lucien lucile lucille lucinda lucio lucious lucius lucky lucretia
lucy ludie ludwig lue luella luetta luigi luis luisa luka lukas luke lula lulu lum luna lupe lura
lurline luster luther lutie luvenia luverne luvinia luz lyda lydell lydia lyla lyle lyman lyn lynda
lyndia lyndon lyndsay lyndsey lynette lynn lynne lynnette lynsey lynwood lyric mabel mabell mabelle
mable mac macarthur mace macel maceo macey machelle maci macie mack mackenzie macy madaline madalyn
madalynn madden maddison maddox madeleine madelene madeline madelyn madelynn madge madie madilyn
madilynn madisen madison madisyn madlyn madonna madyson mae maebell maebelle maegan maeve mafalda
magan magdalen magdalena magdalene magen maggie magnolia mahala mahlon mai maia maida maira maiya
major makai makaila makala makayla makena makenna makenzie makhi malachi malakai malaki malaya
malcolm malcom male maleah malia malik malinda malissa maliyah mallie mallorie mallory malorie
malvin malvina mamie mammie manda mandi mandie mandy manford manley mannie manning mansfield manuel
manuela manuelita mara maralyn maranda marc marcel marcela marcelina marceline marcelino marcella
marcelle marcello marcellus marcelo marchello marci marcia marcie marco marcos marcus marcy mardell
mareli marely maren margaret margarete margarett margaretta margarette margarita margarite margarito
marge margene margery margie margo margot margret marguerite margueritta margurite margy mari maria
mariah mariam marian mariana mariann marianna marianne mariano maribel maribeth maricela marie
mariel mariela marietta marilee marilou marilyn marilynn marin marina mario marion marisa marisela
marisol marissa marita maritza mariyah marjorie marjory mark markel markell markita markus marla
marlana marland marlee marleen marlen marlena marlene marley marlie marlin marlo marlon marlyn
marlys marni marnie marnita marolyn marques marquez marquis marquise marquita marry marsha marshal
marshall mart marta martell martez martha marti martika martin martina martine marty marva marvel
marvin mary maryam maryann maryanne marybelle marybeth maryellen maryjane maryjo marylee marylin
marylou marylouise marylyn masako masao mason mat mateo mathew mathews mathias mathilda mathilde
matias matie matilda matilde matt matteo matthew matthias mattie maud maude maudie maura maureen
maurice mauricio maurine mauro maury maverick mavis max maxie maxim maximilian maximillian maximo
maximus maxine maxwell may maya maybell maybelle maye mayme maymie maynard mayo mayra mazie mcarthur
mckayla mckenna mckenzie mckinley meadow meagan meaghan mearl mechelle meda meg megan meggan meghan
meghann mekhi mel melanie melany melba melbourne melina melinda melisa melissa melissia mellie
mellisa mellissa melodee melodie melody melonie melony melton melva melville melvin melvina melvyn
memphis menachem mendy mercedes meredith merilyn merl merle merlene merlin merlyn merna merri merrie
merrilee merrill merrily merritt merry mertie merton mervin mervyn merwin meryl messiah meta metro
metta mettie meyer mia miah micaela micah micayla michael michaela michaele michal michale micheal
michel michele michelina michell michelle michial mickey mickie micky miesha migdalia miguel
miguelangel mikaela mikaila mikal mikala mikalah mikayla mike mikeal mikel mikhail mila milagros
milan milburn mildred miles miley milford milissa millard miller millicent millie milo milton mimi
mina mindi mindy minerva minna minnie minor minoru minta mira miracle miranda mireya miriah miriam
misael missouri missy misti mistie misty mitch mitchel mitchell mittie mitzi miya moe moesha mohamed
mohammad mohammed moira moises mollie molly mona monica monika monique monna monnie monroe monserrat
montana monte montel montgomery montie montrell montserrat monty moody mordechai morgan moriah
morris mortimer morton mose moses moshe mossie mozell mozella mozelle muhammad muriel murl murphy
murray murry mustafa mya myah mychal myer mykel myla mylee myles mylie myra myranda myrl myrle myrna
myron myrtice myrtie myrtis myrtle nada nadia nadine naima najee nakia nakisha nakita nallely nan
nanci nancie nancy nanette nanie nannette nannie naoma naomi napoleon nash nasir nat natalee natalia
natalie nataly natalya natasha nathalia nathalie nathaly nathan nathanael nathanial nathaniel nathen
natosha nautica nayeli nayely neal ned nedra neha nehemiah neil nelda nelia nell nella nelle nellie
nello nels nelson nena neola neoma nereida nery nestor neta nettie neva nevada nevaeh neveah nevin
newell newman newt newton nia nichelle nichol nicholas nicholaus nichole nick nicki nicklaus
nickolas nicky nico nicola nicolas nicole nicolette nicolle nigel nikhil niki nikia nikita nikki
nikko niko nikolai nikolas nikole nila nilda nile niles nina nira nita noah nobie noble noe noel
noelia noelle noemi nohely nola nolan nolia noma nona nonie nora norah norbert norberto noreen
norene noreta noretta norine norita norma norman normand norris norton norval norwood nova novella
nunzio nya nyah nyasia nyla nylah nyree oakley obie ocie octavia octavio octavius oda odalis odalys
odelia odell odessa odette odie odile odin odis odus ofelia ogden okey ola olaf olan oland ole olen
olene oleta olevia olga olie olin olive oliver olivia ollie olympia oma omar omari omarion omer omie
ona oneal oneida oneta onie onnie opal ophelia ora oral oralia oran orange oren orene orie orin
orion oris orland orlando orlin orlo orma orpha orrie orrin orris orson orval orvel orvil orville
orvin osa osbaldo osborne oscar osie ossie osvaldo oswald oswaldo otelia otha othel otho otis ottie
ottilie ottis otto ouida ova ovid owen ozell ozella ozie ozzie pablo paige paisley paityn palma
palmer paloma pam pamala pamela pamelia pamella pandora pansy paola paralee paris park parker
parrish parthenia pascal pasquale pat pate patience patric patrica patrice patricia patrick patsy
patti pattie patty paul paula pauletta paulette paulina pauline paulo paxton payten payton pearl
pearle pearlene pearlie pearline pearly pedro peggie peggy penelope penni pennie penny pepper
percival percy perla perley pernell perri perry pershing pete peter petra peyton phebe phil philip
phillip phillis philomena phoebe phoenix phylicia phylis phyliss phyllis pierce pierre pink pinkie
pinkney piper pleas pleasant ples pluma pollie polly porfirio porsche porsha porter portia pranav
precious prentice prentiss presley preston price prince princess priscila priscilla prudence qiana
queen queenie quentin quiana quincy quinn quint quinten quintin quinton rachael racheal rachel
rachelle racquel rae raegan raekwon raelynn rafael rafaela raheem rahn rahsaan rahul raiden raina
rakeem raleigh ralph ramiro ramon ramona ramsey rand randal randall randel randell randi randle
randolf randolph randy ransom raoul raphael raquan raquel rashaad rashaan rashad rashawn rasheed
rashida raul raven ray rayan rayburn rayfield rayford raymon raymond raymundo rayna raynard rayne
rayshawn reagan reanna reatha reba rebeca rebecca rebekah reece reed reese refugio regan regena
regenia reggie regina reginal reginald regis reid reilly reina reinaldo reinhold reino remington
rena renada renae renaldo renard renata rene renea renee renita reno ressie reta retha retta reuben
reva rex rexford rey reyes reyna reynaldo reynold reynolds rhea rheta rhett rhianna rhiannon rhoda
rhona rhonda rhys rian rianna ricardo ricci rich richard richelle richie richmond rick rickey ricki
rickie ricky rico ridge rigoberto rihanna rikki riley rilla risa rishi rita ritchie river riya rob
robb robbie robbin robby robert roberta roberto robin robley robt roby robyn rocco rochelle rocio
rock rocky rod roddy roderic roderick rodger rodney rodolfo rodrick rodrigo roe roel rogelio roger
rogers rohan roland rolanda rolando rolf rolla rolland rollie rollin roma romaine roman romello
romeo romie romona ron rona ronal ronald ronaldo ronan ronda rondal roni ronin ronna ronnie ronny
roosevelt rory rosa rosabelle rosalee rosalia rosalie rosalind rosalinda rosaline rosalyn rosamond
rosann rosanna rosanne rosaria rosario rosco roscoe rose roseann roseanna roseanne rosella roselyn
rosemarie rosemary rosena rosendo rosetta rosevelt rosey rosia rosie rosina rosita roslyn ross
rossie roswell rowan rowena rowland roxana roxane roxann roxanna roxanne roxie roy royal royce
rozanne rozella rube ruben rubi rubie rubin ruby rubye rudolf rudolfo rudolph rudy rueben ruel rufus
rupert rush russ russel russell rustin rusty ruth rutha ruthann ruthanne ruthe rutherford ruthie
ryan ryann ryder ryker rylan ryland rylee ryleigh ryley rylie ryne sabastian sabina sable sabra
sabrina sade sadie sadye sage saige sal salena salina sallie sally salma salome salvador salvatore
sam samantha samara samatha samie samir samira sammie sammy sampson samson samual samuel sanaa sanai
sanders sandi sandie sandra sandy sanford saniya saniyah sanjuana sanjuanita santa santana santiago
santina santino santo santos sara sarah sarahi sarai sariah sarina sarita sasha saul saundra savana
savanah savanna savannah saverio savion savon sawyer scarlet scarlett schuyler scot scott scottie
scotty seamus sean sebastian sebrina sedrick selah selena selene selina selma selmer semaj sena
seneca serena serenity sergio serina seth severo seward seymour shad shae shaina shakira shalon
shalonda shamar shameka shamika shan shana shanae shanda shandra shane shaneka shanell shanelle
shanequa shani shania shanice shaniece shanika shaniqua shanita shaniya shanna shannan shannen
shannon shanon shanta shante shantel shantell shaquan shaquana shaquille shaquita shara shardae
sharday sharde sharee sharen shari sharif sharita sharla sharleen sharlene sharman sharon sharonda
sharron sharyl sharyn shasta shatara shaun shauna shaunna shavon shavonne shawanda shawn shawna
shawnda shawnee shawnna shawnte shay shayla shaylee shayna shayne shea shedrick sheena sheila
sheilah shelba shelbi shelbie shelby sheldon shelia shelley shelli shellie shelly shelton shelva
shelvia shelvie shemar shena shenna sheree sheri sheridan sherie sherilyn sherita sherlyn sherman
sheron sherree sherri sherrie sherrill sherron sherry sherryl sherwin sherwood sheryl sheryll sheyla
shianne shiela shiloh shira shirl shirlee shirleen shirlene shirley shirleyann shirlie shoji shon
shona shonda shonna shreya shyann shyanne shyheim shyla sibyl sid sidney siena sienna sierra sigmund
signe sigrid sigurd silas silvester silvia silvio sim simeon simon simone sincere sing siobhan
sister skip sky skye skyla skylar skyler slade sloane smith socorro sofia sol soledad solomon solon
somer sommer son sondra sonia sonja sonji sonny sonya sophia sophie sophronia soren spencer spenser
spring spurgeon stacey staci stacia stacie stacy stafford stan stanford stanislaus stanley stanton
star starla starling starr stasia stefan stefani stefanie stella stephaine stephan stephani
stephania stephanie stephany stephen stephenie stephon sterling stetson stevan steve steven stevie
stewart stone stonewall stoney storm stormy stuart sudie sue suellen sula sullivan summer sumner
sunday sunny sunshine susan susana susann susanna susannah susanne susie suzan suzann suzanna
suzanne suzette suzie suzy sybil syble sydell sydnee sydney sydni sydnie syed sylvan sylvester
sylvia symone syreeta tab tabatha tabetha tabitha tad taft tahj tai taina taj taja takisha tal talan
talen talia taliyah tallie talmadge talmage talon tamala tamara tamatha tambra tameka tamekia tamela
tamera tami tamia tamica tamie tamika tamiko tamisha tammi tammie tammy tamra tamya tana tanesha
tangela tania tanika tanisha taniya taniyah tanja tanner tanya tara tarah tari tarik tariq tarsha
taryn tasha tashina tasia tate tatia tatiana tatianna tatsuo tatum tatyana tatyanna taurean taurus
tavares tavaris tavian tavion tavon tawana tawanda tawanna tawny tawnya taya tayla tayler taylor
tayshaun tea teagan ted teddie teddy teela teena tegan telly tempie tena tenika tenisha tennie
tennille tera terance terell terence teresa terese teressa teri terra terrance terrell terrence
terri terrie terrill terry tess tessa tessie tevin tex thad thaddeus thalia thea theadore theda
thedore thelma theo theodis theodora theodore theola theresa therese theresia therman theron theta
thomas thomasina thor thora thornton thurman thurston thyra tia tiana tianna tiara tiarra tiera
tierra tiesha tiffani tiffanie tiffany tilda tillie tillman tim timmie timmothy timmy timothy tina
tiny tisa tisha tito titus tobe tobi tobias tobie tobin toby toccara tod todd toivo tollie tom toma
tomas tomasa tomeka tomie tomika tommie tommy tonda toney toni tonia tonja tony tonya torey tori
toriano torie torrance torrence torrey torrie torry tory tosha toshiko toshio towanda toy toya trace
tracee tracey traci tracie tracy trae travis travon trayvon tre treasure treena tremaine tremayne
trena trent trenten trenton tresa tressa tressie treva trever trevin trevion trevon trevor trey
treyton treyvon tricia trina trinidad trinity tripp trish trisha trista tristan tristen tristian
tristin triston troy trudi trudie trudy trula trumaine truman trystan tuan tucker tula turner twila
twyla ty tye tyesha tyler tylor tyquan tyra tyree tyreek tyreese tyrek tyreke tyrel tyrell tyrese
tyrik tyrin tyriq tyrique tyron tyrone tyrus tyshawn tyson ula ulises ulysses una unique unknown
unnamed urban uriah uriel urijah ursula vada val valarie valencia valentin valentina valentine
valentino valeria valerie valery valinda vallie valorie van vance vanesa vanessa vannie vashon
vashti vassie vaughn veda vela velda velia vella velma velva velvet vena venessa venice venita
vennie venus veola vera verda verdell verdie vergie vergil verl verla verle verlene verlie verlin
verlon verlyn vern verna vernal verne vernell vernelle verner vernetta vernia vernice vernie vernita
vernon verona veronica versie vertie vesta vester veta veva vic vicente vicie vickey vicki vickie
vicky victor victoria victoriano victory vida vidal vikki vilma vina vince vincent vincenza vincenzo
vinnie vinson viola violet violeta violette vira virdie virgia virgie virgil virginia virgle
viridiana vita vito viva vivian viviana vivien vivienne vlasta volney von vonda vonetta vonnie wade
waino waldemar waldo walker wallace wally walt walter walton wanda waneta wanita ward wardell warner
warren wash washington watson wava waverly wayde wayland waylon wayman waymon wayne webb webster
weldon wellington welton wende wendel wendell wendi wendy werner wes wesley west westley weston
wheeler whit whitley whitney wilber wilbert wilbur wilburn wilda wiley wilford wilfred wilfredo
wilfrid wilhelm wilhelmina wilkie will willa willam willard willene willia william williams willian
williard willie williemae willis willodean willow wilma wilmer wilson wilton windell windy winfield
winford winfred winifred winnie winnifred winona winston winter winthrop winton wm wong woodie
woodroe woodrow woody worth wright wyatt wylie wyman wynona xander xavier xena ximena xiomara
xzavier yaakov yadiel yadira yael yahaira yahir yair yajaira yamilet yamilex yancy yandel yareli
yaretzi yaritza yasmeen yasmin yasmine yazmin yehuda yesenia yessenia yetta yoel yolanda yolonda
yosef yoselin yoshiko yoshio young yuliana yulisa yulissa yurem yuridia yusuf yvette yvonne
zachariah zachary zachery zack zackary zackery zada zadie zaid zaiden zain zaire zakary zana zander
zandra zane zaniyah zara zaria zariah zavier zayden zayne zeb zebulon zechariah zelda zella zelma
zelpha zena zeno zenobia zetta zettie zhane zigmund zina zion zita zoe zoey zoie zola zollie zona
zora zula
`.split(/\s+/).filter(Boolean));
