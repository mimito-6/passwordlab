/* PasswordLab Passphrase Generator — all computation is local. No network requests, no tracking.
   Word list: EFF Short Word List 2.0 (1296 words), embedded verbatim.
   Entropy model: each word is a uniform random pick from the list, so bits = n * log2(1296).
   Crack time assumes the attacker KNOWS the generation method (Kerckhoffs) and brute-forces
   the word space offline at 10 billion guesses/sec — a pessimistic, honest estimate. */
(function (root) {
  "use strict";

  var WORDS = ["aardvark","abandoned","abbreviate","abdomen","abhorrence","abiding","abnormal","abrasion","absorbing","abundant","abyss","academy","accountant","acetone","achiness","acid","acoustics","acquire","acrobat","actress","acuteness","aerosol","aesthetic","affidavit","afloat","afraid","aftershave","again","agency","aggressor","aghast","agitate","agnostic","agonizing","agreeing","aidless","aimlessly","ajar","alarmclock","albatross","alchemy","alfalfa","algae","aliens","alkaline","almanac","alongside","alphabet","already","also","altitude","aluminum","always","amazingly","ambulance","amendment","amiable","ammunition","amnesty","amoeba","amplifier","amuser","anagram","anchor","android","anesthesia","angelfish","animal","anklet","announcer","anonymous","answer","antelope","anxiety","anyplace","aorta","apartment","apnea","apostrophe","apple","apricot","aquamarine","arachnid","arbitrate","ardently","arena","argument","aristocrat","armchair","aromatic","arrowhead","arsonist","artichoke","asbestos","ascend","aseptic","ashamed","asinine","asleep","asocial","asparagus","astronaut","asymmetric","atlas","atmosphere","atom","atrocious","attic","atypical","auctioneer","auditorium","augmented","auspicious","automobile","auxiliary","avalanche","avenue","aviator","avocado","awareness","awhile","awkward","awning","awoke","axially","azalea","babbling","backpack","badass","bagpipe","bakery","balancing","bamboo","banana","barracuda","basket","bathrobe","bazooka","blade","blender","blimp","blouse","blurred","boatyard","bobcat","body","bogusness","bohemian","boiler","bonnet","boots","borough","bossiness","bottle","bouquet","boxlike","breath","briefcase","broom","brushes","bubblegum","buckle","buddhist","buffalo","bullfrog","bunny","busboy","buzzard","cabin","cactus","cadillac","cafeteria","cage","cahoots","cajoling","cakewalk","calculator","camera","canister","capsule","carrot","cashew","cathedral","caucasian","caviar","ceasefire","cedar","celery","cement","census","ceramics","cesspool","chalkboard","cheesecake","chimney","chlorine","chopsticks","chrome","chute","cilantro","cinnamon","circle","cityscape","civilian","clay","clergyman","clipboard","clock","clubhouse","coathanger","cobweb","coconut","codeword","coexistent","coffeecake","cognitive","cohabitate","collarbone","computer","confetti","copier","cornea","cosmetics","cotton","couch","coverless","coyote","coziness","crawfish","crewmember","crib","croissant","crumble","crystal","cubical","cucumber","cuddly","cufflink","cuisine","culprit","cup","curry","cushion","cuticle","cybernetic","cyclist","cylinder","cymbal","cynicism","cypress","cytoplasm","dachshund","daffodil","dagger","dairy","dalmatian","dandelion","dartboard","dastardly","datebook","daughter","dawn","daytime","dazzler","dealer","debris","decal","dedicate","deepness","defrost","degree","dehydrator","deliverer","democrat","dentist","deodorant","depot","deranged","desktop","detergent","device","dexterity","diamond","dibs","dictionary","diffuser","digit","dilated","dimple","dinnerware","dioxide","diploma","directory","dishcloth","ditto","dividers","dizziness","doctor","dodge","doll","dominoes","donut","doorstep","dorsal","double","downstairs","dozed","drainpipe","dresser","driftwood","droppings","drum","dryer","dubiously","duckling","duffel","dugout","dumpster","duplex","durable","dustpan","dutiful","duvet","dwarfism","dwelling","dwindling","dynamite","dyslexia","eagerness","earlobe","easel","eavesdrop","ebook","eccentric","echoless","eclipse","ecosystem","ecstasy","edged","editor","educator","eelworm","eerie","effects","eggnog","egomaniac","ejection","elastic","elbow","elderly","elephant","elfishly","eliminator","elk","elliptical","elongated","elsewhere","elusive","elves","emancipate","embroidery","emcee","emerald","emission","emoticon","emperor","emulate","enactment","enchilada","endorphin","energy","enforcer","engine","enhance","enigmatic","enjoyably","enlarged","enormous","enquirer","enrollment","ensemble","entryway","enunciate","envoy","enzyme","epidemic","equipment","erasable","ergonomic","erratic","eruption","escalator","eskimo","esophagus","espresso","essay","estrogen","etching","eternal","ethics","etiquette","eucalyptus","eulogy","euphemism","euthanize","evacuation","evergreen","evidence","evolution","exam","excerpt","exerciser","exfoliate","exhale","exist","exorcist","explode","exquisite","exterior","exuberant","fabric","factory","faded","failsafe","falcon","family","fanfare","fasten","faucet","favorite","feasibly","february","federal","feedback","feigned","feline","femur","fence","ferret","festival","fettuccine","feudalist","feverish","fiberglass","fictitious","fiddle","figurine","fillet","finalist","fiscally","fixture","flashlight","fleshiness","flight","florist","flypaper","foamless","focus","foggy","folksong","fondue","footpath","fossil","fountain","fox","fragment","freeway","fridge","frosting","fruit","fryingpan","gadget","gainfully","gallstone","gamekeeper","gangway","garlic","gaslight","gathering","gauntlet","gearbox","gecko","gem","generator","geographer","gerbil","gesture","getaway","geyser","ghoulishly","gibberish","giddiness","giftshop","gigabyte","gimmick","giraffe","giveaway","gizmo","glasses","gleeful","glisten","glove","glucose","glycerin","gnarly","gnomish","goatskin","goggles","goldfish","gong","gooey","gorgeous","gosling","gothic","gourmet","governor","grape","greyhound","grill","groundhog","grumbling","guacamole","guerrilla","guitar","gullible","gumdrop","gurgling","gusto","gutless","gymnast","gynecology","gyration","habitat","hacking","haggard","haiku","halogen","hamburger","handgun","happiness","hardhat","hastily","hatchling","haughty","hazelnut","headband","hedgehog","hefty","heinously","helmet","hemoglobin","henceforth","herbs","hesitation","hexagon","hubcap","huddling","huff","hugeness","hullabaloo","human","hunter","hurricane","hushing","hyacinth","hybrid","hydrant","hygienist","hypnotist","ibuprofen","icepack","icing","iconic","identical","idiocy","idly","igloo","ignition","iguana","illuminate","imaging","imbecile","imitator","immigrant","imprint","iodine","ionosphere","ipad","iphone","iridescent","irksome","iron","irrigation","island","isotope","issueless","italicize","itemizer","itinerary","itunes","ivory","jabbering","jackrabbit","jaguar","jailhouse","jalapeno","jamboree","janitor","jarring","jasmine","jaundice","jawbreaker","jaywalker","jazz","jealous","jeep","jelly","jeopardize","jersey","jetski","jezebel","jiffy","jigsaw","jingling","jobholder","jockstrap","jogging","john","joinable","jokingly","journal","jovial","joystick","jubilant","judiciary","juggle","juice","jujitsu","jukebox","jumpiness","junkyard","juror","justifying","juvenile","kabob","kamikaze","kangaroo","karate","kayak","keepsake","kennel","kerosene","ketchup","khaki","kickstand","kilogram","kimono","kingdom","kiosk","kissing","kite","kleenex","knapsack","kneecap","knickers","koala","krypton","laboratory","ladder","lakefront","lantern","laptop","laryngitis","lasagna","latch","laundry","lavender","laxative","lazybones","lecturer","leftover","leggings","leisure","lemon","length","leopard","leprechaun","lettuce","leukemia","levers","lewdness","liability","library","licorice","lifeboat","lightbulb","likewise","lilac","limousine","lint","lioness","lipstick","liquid","listless","litter","liverwurst","lizard","llama","luau","lubricant","lucidity","ludicrous","luggage","lukewarm","lullaby","lumberjack","lunchbox","luridness","luscious","luxurious","lyrics","macaroni","maestro","magazine","mahogany","maimed","majority","makeover","malformed","mammal","mango","mapmaker","marbles","massager","matchstick","maverick","maximum","mayonnaise","moaning","mobilize","moccasin","modify","moisture","molecule","momentum","monastery","moonshine","mortuary","mosquito","motorcycle","mousetrap","movie","mower","mozzarella","muckiness","mudflow","mugshot","mule","mummy","mundane","muppet","mural","mustard","mutation","myriad","myspace","myth","nail","namesake","nanosecond","napkin","narrator","nastiness","natives","nautically","navigate","nearest","nebula","nectar","nefarious","negotiator","neither","nemesis","neoliberal","nephew","nervously","nest","netting","neuron","nevermore","nextdoor","nicotine","niece","nimbleness","nintendo","nirvana","nuclear","nugget","nuisance","nullify","numbing","nuptials","nursery","nutcracker","nylon","oasis","oat","obediently","obituary","object","obliterate","obnoxious","observer","obtain","obvious","occupation","oceanic","octopus","ocular","office","oftentimes","oiliness","ointment","older","olympics","omissible","omnivorous","oncoming","onion","onlooker","onstage","onward","onyx","oomph","opaquely","opera","opium","opossum","opponent","optical","opulently","oscillator","osmosis","ostrich","otherwise","ought","outhouse","ovation","oven","owlish","oxford","oxidize","oxygen","oyster","ozone","pacemaker","padlock","pageant","pajamas","palm","pamphlet","pantyhose","paprika","parakeet","passport","patio","pauper","pavement","payphone","pebble","peculiarly","pedometer","pegboard","pelican","penguin","peony","pepperoni","peroxide","pesticide","petroleum","pewter","pharmacy","pheasant","phonebook","phrasing","physician","plank","pledge","plotted","plug","plywood","pneumonia","podiatrist","poetic","pogo","poison","poking","policeman","poncho","popcorn","porcupine","postcard","poultry","powerboat","prairie","pretzel","princess","propeller","prune","pry","pseudo","psychopath","publisher","pucker","pueblo","pulley","pumpkin","punchbowl","puppy","purse","pushup","putt","puzzle","pyramid","python","quarters","quesadilla","quilt","quote","racoon","radish","ragweed","railroad","rampantly","rancidity","rarity","raspberry","ravishing","rearrange","rebuilt","receipt","reentry","refinery","register","rehydrate","reimburse","rejoicing","rekindle","relic","remote","renovator","reopen","reporter","request","rerun","reservoir","retriever","reunion","revolver","rewrite","rhapsody","rhetoric","rhino","rhubarb","rhyme","ribbon","riches","ridden","rigidness","rimmed","riptide","riskily","ritzy","riverboat","roamer","robe","rocket","romancer","ropelike","rotisserie","roundtable","royal","rubber","rudderless","rugby","ruined","rulebook","rummage","running","rupture","rustproof","sabotage","sacrifice","saddlebag","saffron","sainthood","saltshaker","samurai","sandworm","sapphire","sardine","sassy","satchel","sauna","savage","saxophone","scarf","scenario","schoolbook","scientist","scooter","scrapbook","sculpture","scythe","secretary","sedative","segregator","seismology","selected","semicolon","senator","septum","sequence","serpent","sesame","settler","severely","shack","shelf","shirt","shovel","shrimp","shuttle","shyness","siamese","sibling","siesta","silicon","simmering","singles","sisterhood","sitcom","sixfold","sizable","skateboard","skeleton","skies","skulk","skylight","slapping","sled","slingshot","sloth","slumbering","smartphone","smelliness","smitten","smokestack","smudge","snapshot","sneezing","sniff","snowsuit","snugness","speakers","sphinx","spider","splashing","sponge","sprout","spur","spyglass","squirrel","statue","steamboat","stingray","stopwatch","strawberry","student","stylus","suave","subway","suction","suds","suffocate","sugar","suitcase","sulphur","superstore","surfer","sushi","swan","sweatshirt","swimwear","sword","sycamore","syllable","symphony","synagogue","syringes","systemize","tablespoon","taco","tadpole","taekwondo","tagalong","takeout","tallness","tamale","tanned","tapestry","tarantula","tastebud","tattoo","tavern","thaw","theater","thimble","thorn","throat","thumb","thwarting","tiara","tidbit","tiebreaker","tiger","timid","tinsel","tiptoeing","tirade","tissue","tractor","tree","tripod","trousers","trucks","tryout","tubeless","tuesday","tugboat","tulip","tumbleweed","tupperware","turtle","tusk","tutorial","tuxedo","tweezers","twins","tyrannical","ultrasound","umbrella","umpire","unarmored","unbuttoned","uncle","underwear","unevenness","unflavored","ungloved","unhinge","unicycle","unjustly","unknown","unlocking","unmarked","unnoticed","unopened","unpaved","unquenched","unroll","unscrewing","untied","unusual","unveiled","unwrinkled","unyielding","unzip","upbeat","upcountry","update","upfront","upgrade","upholstery","upkeep","upload","uppercut","upright","upstairs","uptown","upwind","uranium","urban","urchin","urethane","urgent","urologist","username","usher","utensil","utility","utmost","utopia","utterance","vacuum","vagrancy","valuables","vanquished","vaporizer","varied","vaseline","vegetable","vehicle","velcro","vendor","vertebrae","vestibule","veteran","vexingly","vicinity","videogame","viewfinder","vigilante","village","vinegar","violin","viperfish","virus","visor","vitamins","vivacious","vixen","vocalist","vogue","voicemail","volleyball","voucher","voyage","vulnerable","waffle","wagon","wakeup","walrus","wanderer","wasp","water","waving","wheat","whisper","wholesaler","wick","widow","wielder","wifeless","wikipedia","wildcat","windmill","wipeout","wired","wishbone","wizardry","wobbliness","wolverine","womb","woolworker","workbasket","wound","wrangle","wreckage","wristwatch","wrongdoing","xerox","xylophone","yacht","yahoo","yard","yearbook","yesterday","yiddish","yield","yo-yo","yodel","yogurt","yuppie","zealot","zebra","zeppelin","zestfully","zigzagged","zillion","zipping","zirconium","zodiac","zombie","zookeeper","zucchini"];
  var GUESSES_PER_SEC = 10000000000;
  var BITS_PER_WORD = Math.log(WORDS.length) / Math.log(2); // log2(1296) ≈ 10.34

  function entropyBits(n, capitalize) {
    var bits = n * BITS_PER_WORD;
    if (capitalize) bits += Math.log(n) / Math.log(2); // one random word capitalized: n choices
    return bits;
  }

  function crackSeconds(bits) {
    return Math.pow(2, bits) / GUESSES_PER_SEC;
  }

  function formatDuration(seconds) {
    if (!isFinite(seconds)) return "effectively forever";
    if (seconds < 1) return "instantly";
    var units = [
      [31557600, "year"], [86400, "day"], [3600, "hour"], [60, "minute"], [1, "second"]
    ];
    for (var i = 0; i < units.length; i++) {
      if (seconds >= units[i][0] * 0.95) {
        var v = seconds / units[i][0];
        var shown = v >= 100 ? Math.round(v).toString() : v.toFixed(1);
        return shown + " " + units[i][1] + (shown === "1.0" || shown === "1" ? "" : "s");
      }
    }
    return seconds.toFixed(2) + " seconds";
  }

  function formatCombinations(n, capitalize) {
    var combos = Math.pow(WORDS.length, n) * (capitalize ? n : 1);
    return "~" + combos.toExponential(1).replace("e+", " × 10^");
  }

  function verdict(bits) {
    if (bits < 45) return ["weak", "weak"];
    if (bits < 70) return ["moderate", "fair"];
    if (bits < 90) return ["strong", "strong"];
    return ["very strong", "strong"];
  }

  // rng: function returning a uniform integer in [0, max). Defaults to crypto.getRandomValues
  // with rejection sampling (no modulo bias).
  function defaultRng(max) {
    var buf = new Uint16Array(1);
    var limit = 65536 - (65536 % max);
    var v;
    do {
      (root.crypto || window.crypto).getRandomValues(buf);
      v = buf[0];
    } while (v >= limit);
    return v % max;
  }

  function generate(n, rng) {
    rng = rng || defaultRng;
    var words = [];
    for (var i = 0; i < n; i++) words.push(WORDS[rng(WORDS.length)]);
    var capIndex = -1;
    return { words: words, capIndex: capIndex };
  }

  function applyCapitalize(gen, rng) {
    rng = rng || defaultRng;
    gen.capIndex = rng(gen.words.length);
    return gen;
  }

  function render(gen, separator) {
    return gen.words.map(function (w, i) {
      if (i === gen.capIndex) return w.charAt(0).toUpperCase() + w.slice(1);
      return w;
    }).join(separator);
  }

  // ---- DOM wiring (browser only) ----
  function init() {
    var $ = function (id) { return document.getElementById(id); };
    if (!$("genBtn")) return;
    var count = $("wordCount"), countLabel = $("countLabel");
    function syncLabel() { countLabel.textContent = count.value; }
    count.addEventListener("input", syncLabel); syncLabel();

    function run() {
      var n = parseInt(count.value, 10);
      var sep = document.querySelector('input[name="sep"]:checked').value;
      var cap = $("capCheck").checked;
      var gen = generate(n);
      if (cap) applyCapitalize(gen);
      var phrase = render(gen, sep);
      var bits = entropyBits(n, cap);
      var secs = crackSeconds(bits);
      var v = verdict(bits);
      $("output").textContent = phrase;
      $("result").hidden = false;
      $("entropy").textContent = bits.toFixed(1) + " bits";
      $("combos").textContent = formatCombinations(n, cap);
      $("bignum").textContent = formatDuration(secs);
      var ve = $("verdict");
      ve.textContent = v[0].toUpperCase();
      ve.className = "verdict " + v[1];
      $("modelNote").textContent = "Estimate — attacker knows the method; offline attack at 10 billion guesses/sec.";
    }
    $("genBtn").addEventListener("click", run);
    $("copyBtn").addEventListener("click", function () {
      var text = $("output").textContent;
      navigator.clipboard.writeText(text).then(function () {
        $("copyHint").hidden = false;
        setTimeout(function () { $("copyHint").hidden = true; }, 2500);
      });
    });
    run(); // generate one on load
  }
  if (typeof document !== "undefined") {
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
    else init();
  }

  var api = {
    WORDS: WORDS, entropyBits: entropyBits, crackSeconds: crackSeconds,
    formatDuration: formatDuration, formatCombinations: formatCombinations,
    verdict: verdict, generate: generate, applyCapitalize: applyCapitalize, render: render
  };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.PassGen = api;
})(typeof self !== "undefined" ? self : this);
