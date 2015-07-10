define [
  'require'
  'soteria.credential-service'
  'soteria.mock.directory-api'
], (require) ->

  CredentialService = require 'soteria.credential-service'
  MockDirectoryApi  = require 'soteria.mock.directory-api'

  # mock
  # ====

  CREDS = {username: 'demo', password: 'demo', realm: 'krypt'}

  EXPECTED_KEYPAIR = {
    privateKey: {
      n: {
        data: [222545727, 111370167, 149803429, 33968576, 60418545, 189514377, 118055659, 201737042,
          7599843, 150494423, 84189912, 232074209, 227852033, 95860691, 118928052, 164635224,
          50351226, 80372630, 67284029, 80064506, 131733665, 17387622, 239775510, 139942609,
          205799954, 222537935, 194607896, 3523973, 268177798, 255641988, 110160146, 14150998,
          3571435, 197388622, 43679312, 119209217, 77339098, 262105875, 140320593, 61892555,
          170069956, 194732766, 217871329, 241660704, 122821570, 62290337, 153110160, 200195153,
          171288192, 164206883, 215086193, 38347829, 36306102, 201968773, 57111848, 115824837,
          210609488, 181731611, 75198180, 42871160, 83901621, 155116613, 84169018, 143511326,
          74242927, 257167319, 139774257, 136208457, 239671897, 106566286, 145089267, 153545065,
          160516770, 3308810, 11506628, 71692862, 60003744, 146376780, 123223490, 10857150,
          87649819, 176270759, 172591497, 43619313, 39461038, 135928646, 69225154, 202323302,
          127506695, 105879697, 229880061, 204585054, 22572974, 172574186, 118591489, 75930326,
          192201226, 77187389, 78730933, 226647492, 31378147, 253516028, 210003247, 117382592,
          84548418, 225241963, 24301051, 251545806, 62490642, 55991566, 249164837, 223649459,
          7395519, 108185729, 828860, 33695514, 35183285, 101424618, 250035553, 10625828, 216550219,
          257404322, 166804886, 15203399, 116707231, 81333814, 137953765, 70999727, 198906592,
          261785708, 35539127, 209347398, 257228926, 212363222, 171877008, 214863127, 123045509,
          139185455, 245360577, 121638240, 258849409, 186819767, 184138359, 232771526, 31172010,
          120726739, 150
        ],
        t: 147,
        s: 0
      },
      e: {
        data: [65537],
        t: 1,
        s: 0
      },
      d: {
        data: [7214657, 16981506, 258832066, 167976384, 64942678, 106602792, 4705951, 166489535,
          2391217, 176263935, 164191117, 121342973, 218833211, 102935703, 176131184, 101060817,
          52946877, 197017182, 73909951, 211145355, 181321629, 78481564, 92592053, 111061422,
          62595813, 156211815, 233671587, 65913642, 131603145, 155376885, 250941162, 264379121,
          202589093, 113636997, 63233274, 83244740, 231784253, 233437610, 128331503, 266823169,
          9924975, 170930283, 181955533, 98090489, 172335366, 158564342, 38582085, 163751373,
          66431419, 22633969, 251498837, 97566028, 208547391, 58278268, 122256734, 91827415,
          168822154, 119877946, 245927805, 106022286, 93537356, 66164953, 255257558, 181994655,
          42500038, 170093603, 262076775, 81837891, 155901336, 148694151, 38261671, 35889172,
          73549270, 51775721, 223122015, 77247955, 148172143, 36060057, 146400472, 190150559,
          125456170, 155309483, 41800935, 262407293, 72460925, 79713131, 30683656, 64764320,
          121128323, 75500221, 59982063, 261768472, 238085451, 192058350, 37288624, 218249064,
          117315553, 27392208, 38597330, 72750967, 68627525, 57860281, 29110178, 120894970,
          100775081, 13377595, 245253372, 4604842, 192805435, 77000704, 99286941, 179127554,
          236278299, 18557400, 77396776, 236598072, 197690979, 77462497, 264190191, 187329711,
          240646740, 231857834, 10092426, 195826595, 215828382, 73037292, 26165314, 78972108,
          97417654, 40322740, 249784331, 131492317, 28543379, 245614443, 223342404, 187854934,
          38746330, 150795037, 198953028, 144062207, 182369972, 49774654, 153350286, 212279969,
          43855437, 223493179, 17
        ],
        t: 147,
        s: 0
      },
      p: {
        data: [166169451, 136148771, 121846149, 211982318, 127274948, 222440779, 116064608,
          120682039, 133687602, 211801532, 44597335, 194719691, 48316683, 79653454, 155842086,
          197494803, 231024349, 202634084, 47971504, 180852045, 164199985, 65153384, 241494504,
          211714048, 115014821, 82933567, 107269007, 236984269, 217267352, 40350351, 236562279,
          258620603, 129330064, 132157938, 103884808, 98884087, 27828327, 82609781, 138644766,
          252476577, 170047620, 70805952, 69834826, 239726830, 49683714, 266764664, 185899536,
          250473040, 251796961, 66827809, 229147152, 162893718, 139727549, 202231269, 212358227,
          83701276, 130674455, 149081651, 88583584, 10192320, 16572043, 56719909, 10052664,
          41265997, 263772919, 82727832, 13320344, 169017671, 198148724, 246912731, 219263867,
          142907631, 62755946, 13
        ],
        t: 74,
        s: 0
      },
      q: {
        data: [102702205, 170260808, 241365312, 241071597, 154326806, 122665621, 208365271,
          206547909, 195744434, 96310812, 158628436, 75912691, 222873016, 140224883, 96528466,
          110950097, 210898425, 74170822, 31763356, 60558979, 17549083, 247284108, 16947543,
          84700072, 76637181, 210195424, 121218224, 194853095, 113694056, 209749151, 178149534,
          206435993, 215868243, 191229787, 95090127, 31357902, 45128447, 46540585, 52667104,
          252902267, 246544541, 184999926, 166544466, 235458937, 83895107, 207246902, 204662717,
          6464951, 226220353, 218916069, 167636802, 222844605, 169172291, 221925550, 238999503,
          70096233, 36705618, 195185991, 178753138, 266808522, 56077366, 6068469, 102359762,
          11051673, 85431669, 167860183, 78504453, 254554295, 18113497, 92501373, 70915629,
          91356797, 98948230, 11
        ],
        t: 74,
        s: 0
      },
      dP: {
        data: [253330989, 190743412, 49553659, 114252428, 109930344, 260389905, 122797370,
          217988373, 79513771, 49850527, 135674129, 86322138, 69219433, 5514748, 165063233,
          251062126, 93470300, 169414565, 216856890, 191176315, 224737438, 207392634, 154149459,
          252313849, 189832785, 13278834, 91878026, 235468034, 252765048, 183964278, 98814458,
          40821443, 197634156, 237334497, 121782932, 53432086, 258734165, 111754211, 47674575,
          88122044, 61319076, 222968377, 249344811, 211372579, 124409933, 227033308, 134405843,
          236487964, 226332849, 199264944, 225947338, 244676803, 232966015, 76120616, 11591726,
          223090907, 179554266, 231329264, 17068925, 62519937, 201154313, 263330951, 75717423,
          97411545, 189578741, 154431910, 254855738, 1913358, 81652439, 61454167, 108363580,
          43417766, 135078486, 8
        ],
        t: 74,
        s: 0
      },
      dQ: {
        data: [20813161, 78730996, 153524539, 77439820, 14949111, 177825407, 184366787, 180762676,
          40647079, 67181846, 264264839, 136847753, 207927301, 192630369, 3029081, 123486383,
          77314814, 108410284, 43421344, 225880720, 11122580, 84831453, 110137257, 95924511,
          170543717, 84010083, 242393593, 27966062, 179268804, 57103379, 122927645, 229719986,
          184097798, 15901204, 256931196, 176084793, 264593698, 112736819, 169967114, 199238911,
          68043475, 2330994, 9287875, 37926981, 128275251, 96482976, 59041781, 190240066, 187887747,
          197731718, 117711998, 181595856, 156163160, 247276125, 242531525, 220926969, 199742632,
          72556398, 59909756, 216208586, 51623283, 212070689, 72682536, 57785470, 88662817, 8352960,
          81174008, 262389693, 98090443, 132681059, 246570125, 221626105, 80250699, 9
        ],
        t: 74,
        s: 0
      },
      qInv: {
        data: [222361456, 220264217, 264673992, 199527380, 150563498, 109172980, 206968739,
          37302694, 165605530, 227850900, 72620201, 121534929, 42790780, 145948985, 204982899,
          214016356, 52959166, 145471551, 86140622, 58101888, 179240832, 210455944, 172732393,
          238254160, 50686447, 148404099, 7079394, 115552887, 189545240, 27098188, 46305815,
          132522696, 89220675, 137309491, 242137903, 43446864, 90572389, 2864827, 101279674,
          237955423, 116987634, 86648096, 67345509, 138711757, 135020080, 49379385, 87309433,
          5911979, 61596920, 14030961, 172897103, 230020816, 3573194, 143700871, 220346531,
          244720003, 114836232, 32690668, 257797424, 180659507, 175799644, 37218799, 78443894,
          34134418, 84514356, 101939060, 96260591, 95866298, 20708341, 10082503, 37409148, 8225617,
          241800409, 2
        ],
        t: 74,
        s: 0
      }
    },
    publicKey: {
      n: {
        data: [222545727, 111370167, 149803429, 33968576, 60418545, 189514377, 118055659, 201737042,
          7599843, 150494423, 84189912, 232074209, 227852033, 95860691, 118928052, 164635224,
          50351226, 80372630, 67284029, 80064506, 131733665, 17387622, 239775510, 139942609,
          205799954, 222537935, 194607896, 3523973, 268177798, 255641988, 110160146, 14150998,
          3571435, 197388622, 43679312, 119209217, 77339098, 262105875, 140320593, 61892555,
          170069956, 194732766, 217871329, 241660704, 122821570, 62290337, 153110160, 200195153,
          171288192, 164206883, 215086193, 38347829, 36306102, 201968773, 57111848, 115824837,
          210609488, 181731611, 75198180, 42871160, 83901621, 155116613, 84169018, 143511326,
          74242927, 257167319, 139774257, 136208457, 239671897, 106566286, 145089267, 153545065,
          160516770, 3308810, 11506628, 71692862, 60003744, 146376780, 123223490, 10857150,
          87649819, 176270759, 172591497, 43619313, 39461038, 135928646, 69225154, 202323302,
          127506695, 105879697, 229880061, 204585054, 22572974, 172574186, 118591489, 75930326,
          192201226, 77187389, 78730933, 226647492, 31378147, 253516028, 210003247, 117382592,
          84548418, 225241963, 24301051, 251545806, 62490642, 55991566, 249164837, 223649459,
          7395519, 108185729, 828860, 33695514, 35183285, 101424618, 250035553, 10625828, 216550219,
          257404322, 166804886, 15203399, 116707231, 81333814, 137953765, 70999727, 198906592,
          261785708, 35539127, 209347398, 257228926, 212363222, 171877008, 214863127, 123045509,
          139185455, 245360577, 121638240, 258849409, 186819767, 184138359, 232771526, 31172010,
          120726739, 150
        ],
        t: 147,
        s: 0
      },
      e: {
        data: [65537],
        t: 1,
        s: 0
      }
    }
  }

  # setup
  # =====

  {credentialService} = {}

  beforeEach ->
    credentialService              = new CredentialService()
    credentialService.directoryApi = new MockDirectoryApi()

  describe 'CredentialService', ->

    describe '#deriveCredential', ->

      it 'should derive a hex key by decrypting a salt from the directory service', (done) ->
        credentialService.deriveCredential(CREDS)
        .then (derived) ->
          expect(derived).toBe('c1cc09e15a4529fcc50b57efde163dd2a9731d31be629fd9df4fd13bc70134f6')
          done()

    describe '#deriveKeypair', ->

      it 'should derive a keypair by loading and decrypting rsa keys from directory', (done) ->
        credentialService.deriveKeypair(CREDS)
        .then (keypair) ->
          expect(JSON.parse(JSON.stringify(keypair))).toEqual(EXPECTED_KEYPAIR)
          done()
