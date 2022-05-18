import base64
import random
import sys
from time import time
import matplotlib.pyplot as pl

RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

# S-box and Inverse S-box (S is for Substitution)
S = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9,
     0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f,
     0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07,
     0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3,
     0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58,
     0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3,
     0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f,
     0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
     0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac,
     0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a,
     0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70,
     0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
     0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42,
     0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]


def generate_key(K):
    """
    cette fonction genère les 11 clés aes-128 en partant de la clé maitresse
    :param K: clé maitresse
    :return: calendrier de clé aes-128
    """
    assert len(K) == 32

    calendrier = []
    calendrier.append(K)
    K = base64.b16decode(K, casefold=True)
    for r in range(10):
        K_new = []
        K_new.append(K[0] ^ S[K[13]] ^ RCON[r])
        K_new.append(K[1] ^ S[K[14]])
        K_new.append(K[2] ^ S[K[15]])
        K_new.append(K[3] ^ S[K[12]])
        K_new.append(K[4] ^ K_new[0])
        K_new.append(K[5] ^ K_new[1])
        K_new.append(K[6] ^ K_new[2])
        K_new.append(K[7] ^ K[3] ^ S[K[12]])
        K_new.append(K[8] ^ K_new[4])
        K_new.append(K[9] ^ K_new[5])
        K_new.append(K[10] ^ K_new[6])
        K_new.append(K[11] ^ K[7] ^ K[3] ^ S[K[12]])
        K_new.append(K[12] ^ K_new[8])
        K_new.append(K[13] ^ K_new[9])
        K_new.append(K[14] ^ K_new[10])
        K_new.append(K[15] ^ K[11] ^ K[7] ^ K[3] ^ S[K[12]])

        result = ""
        for i in range(len(K_new)):
            c = K_new[i]
            result = result + hex(c)[2:].zfill(2)
        calendrier.append(result)
        K = base64.b16decode(result, casefold=True)

    return calendrier


def brout_key(k, p):
    """
    créér un calendrier de clé brouté
    :param k:  la clé
    :param p: probabilité de brutage
    :return:
    """
    assert 0 <= p <= 100
    assert len(k) == 32
    k = bin(int(k, 16))[2:].zfill(128)
    k_new = ""
    for i in range(len(k)):
        if k[i] == '1':
            n = random.randint(0, 99)
            if p > n:
                k_new = k_new + '0'
            else:
                k_new = k_new + '1'
        else:
            k_new = k_new + k[i]
    k_new = hex(int(k_new, 2))[2:].zfill(32)
    return k_new


def brut_schedule(calendrier, p):
    """
    deteriore un calendrier de clé
    :param calendrier:  calendrier
    :param p: probabilité d'erreur
    :return: calendrier bruté
    """
    new_calendrier = []
    for i in calendrier:
        new_calendrier.append(brout_key(i, p))
    return new_calendrier


def is_candida_128(k1, k2):
    assert len(k1) == len(k2)
    """
    calcule le nombre de bites 1 --> 0
    :param k1: clé à tester
    :param k2: clé de base
    :return:
    """
    k1bin = bin(int(k1, 16))[2:].zfill(128)
    k2bin = bin(int(k2, 16))[2:].zfill(128)
    result = True
    i = 0
    while i < len(k2bin):
        if k1bin[i] != k2bin[i]:
            if k1bin[i] != '1':
                result = False
            if k2bin[i] != '0':
                result = False
        i = i + 1
    return result


def is_candidat(k1, k2):
    assert len(k1) == len(k2)
    """
    calcule le nombre de bites 1 --> 0
    :param k1: clé à tester
    :param k2: clé de base
    :return:
    """
    n = len(k1) * 4
    k1bin = bin(int(k1, 16))[2:].zfill(n)
    k2bin = bin(int(k2, 16))[2:].zfill(n)
    result = True
    i = 0
    while i < n:
        if k1bin[i] != k2bin[i]:
            if k1bin[i] != '1':
                result = False
            if k2bin[i] != '0':
                result = False
        i = i + 1
    return result


def soustab_z(k):
    tab = []
    for i in range(len(k)):
        if k[i] == '0':
            tmp = k[0:i] + '1' + k[i+1:len(k)]
            tab.append(tmp)
    return tab


def combinaison_z(k):
    """
    genère toutes les combinaisons possibles d'un octet par le canal z
    :param k: un octet
    :return: les combinaisons possibles
    """
    k = bin(int(k, 16))[2:].zfill(8)
    liste = soustab_z(k)
    new_list = liste
    new_list.append(k)
    #print(new_list)
    while liste[0] != "11111111":
        n = len(liste)
        fils = []
        for i in range(n):
            tmp = soustab_z(liste[i])
            sous_fils = []
            for k in range(len(tmp)):
                sous_fils.append(tmp[k])
            for t in range(len(sous_fils)):
                fils.append(sous_fils[t])
        liste = fils
        #print(len(liste))
        for i in range(len(liste)):
            new_list.append(liste[i])
        #print(new_list)
    # on supprime les doublons
    new_list = list(set(new_list))
    #print(new_list)
    # on convertit en hexa
    result = []
    for i in range(len(new_list)):
        result.append((hex(int(new_list[i], 2)))[2:].zfill(2))
    return result


def forme_colonne(l1, l2, l3, l4, n=1):
    """
    genère les toutes les combinaisons possibles d'une colonne
    en partant des differentes combibaisons des ses octets
    :param l1: liste d'octet
    :param l2: liste d'octet
    :param l3: liste d'octet
    :param l4: liste d'octet
    :param n: pour savoir si on se trouve à la 4eme colonne auquelle Rotword a été appliquée
    :return: les combinaisons possibles d'une colonnes
    """
    colonne = []
    for a in  l1:
        for b in l2:
            for c in l3:
                for d in l4:
                    if n == 1:
                        colonne.append(a+b+c+d)
                    else:
                        colonne.append(d + a + b + c)
    return colonne


def check_key(schedule1, schedule2):
    """
    teste si le schedule1 ==> schedule2 via le canal Z
    :return: vrai si schedule1 --> schedule2
    """
    result = True
    for i in range(1, len(schedule1)):
        if not is_candidat(schedule1[i], schedule2[i]):
            result = False
    return result


def attack(k0, k1, brut):
    correct_key = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    colonne = [0, 0, 0, 0, 0, 0, 0, 0]
    # 1ere case
    k0 = base64.b16decode(k0, casefold=True)
    k1 = base64.b16decode(k1, casefold=True)
    c11 = []
    c41 = [] # rotword deja appliqué
    cc11 = []

    c12 = []
    c42 = []  # rotword deja appliqué
    cc12 = []

    c13 = []
    c43 = []  # rotword deja appliqué
    cc13 = []

    c14 = []
    c44 = []  # rotword deja appliqué
    cc14 = []

    #1ere case
    if k0[0] ^ S[k0[13]] ^ RCON[0] == k1[0]:
        colonne[0] = k0[0] ^ S[k0[13]] ^ RCON[0]
        correct_key[0] = hex(k0[0])[2:].zfill(2)
        correct_key[13] = hex(k0[13])[2:].zfill(2)
        c11.append(correct_key[0])
        c41.append(correct_key[13])
        cc11.append(hex(k1[0])[2:].zfill(2))
    else:
        f1 = combinaison_z(hex(k0[0])[2:].zfill(2))
        f2 = combinaison_z(hex(k0[13])[2:].zfill(2))
        octet_reference = hex((k1[0]))[2:].zfill(2)
        possibles = []
        for i in f1:
            for k in f2:
                    a = base64.b16decode(i, casefold=True)
                    b = base64.b16decode(k, casefold=True)
                    c = a[0] ^ S[b[0]] ^ RCON[0]
                    c = hex(c)[2:].zfill(2)
                    # on va tester si c est une possibilité
                    if is_candidat(c, octet_reference) and is_candidat(i, hex(k0[0])[2:].zfill(2)) and is_candidat(k, hex(k0[13])[2:].zfill(2)):
                        possibles.append((c, i, k))
                        c11.append(i)
                        c41.append(k)
                        cc11.append(c)

        # 2e case
    if k0[1] ^ S[k0[14]] == k1[1]:
        correct_key[1] = hex(k0[1])[2:].zfill(2)
        correct_key[14] = hex(k0[14])[2:].zfill(2)
        colonne[1] = k0[1] ^ S[k0[14]]
        c12.append(correct_key[1])
        c42.append(correct_key[14])
        cc12.append(hex(k1[1])[2:].zfill(2))
    else:
        f1 = combinaison_z(hex(k0[1])[2:].zfill(2))
        f2 = combinaison_z(hex(k0[14])[2:].zfill(2))
        octet_reference = hex((k1[1]))[2:].zfill(2)
        possibles = []
        for i in f1:
            for k in f2:
                if i != hex(k0[1])[2:].zfill(2) and k != hex(k0[14])[2:].zfill(2):
                    a = base64.b16decode(i, casefold=True)
                    b = base64.b16decode(k, casefold=True)
                    c = a[0] ^ S[b[0]]
                    c = hex(c)[2:].zfill(2)
                    # on va tester si c est une possibilité
                    if is_candidat(c, octet_reference) and is_candidat(i, hex(k0[1])[2:].zfill(2)) and is_candidat(k, hex(k0[14])[2:].zfill(2)):
                        possibles.append((c, i, k))
                        c12.append(i)
                        c42.append(k)
                        cc12.append(c)

    # 3e case
    if k0[2] ^ S[k0[15]] == k1[2]:
        correct_key[2] = hex(k0[2])[2:].zfill(2)
        correct_key[15] = hex(k0[15])[2:].zfill(2)
        colonne[2] = k0[2] ^ S[k0[15]]
        c13.append(correct_key[2])
        c43.append(correct_key[15])
        cc13.append(hex(k1[2])[2:].zfill(2))
    else:
        f1 = combinaison_z(hex(k0[2])[2:].zfill(2))
        f2 = combinaison_z(hex(k0[15])[2:].zfill(2))
        octet_reference = hex((k1[2]))[2:].zfill(2)
        possibles = []
        for i in f1:
            for k in f2:
                a = base64.b16decode(i, casefold=True)
                b = base64.b16decode(k, casefold=True)
                c = a[0] ^ S[b[0]]
                c = hex(c)[2:].zfill(2)
                # on va tester si c est une possibilité

                if is_candidat(c, octet_reference) and is_candidat(i, hex(k0[2])[2:].zfill(2)) and is_candidat(k, hex(k0[15])[2:].zfill(2)):
                    possibles.append((c, i, k))
                    c13.append(i)
                    c43.append(k)
                    cc13.append(c)

    # 4e case
    if k0[3] ^ S[k0[12]] == k1[3]:
        correct_key[3] = hex(k0[3])[2:].zfill(2)
        correct_key[12] = hex(k0[12])[2:].zfill(2)
        colonne[3] = k0[3] ^ S[k0[12]]
        c14.append(correct_key[3])
        c44.append(correct_key[12])
        cc14.append(hex(k1[3])[2:].zfill(2))
    else:
        f1 = combinaison_z(hex(k0[3])[2:].zfill(2))
        f2 = combinaison_z(hex(k0[12])[2:].zfill(2))
        octet_reference = hex((k1[3]))[2:].zfill(2)
        possibles = []
        for i in f1:
            for k in f2:
                a = base64.b16decode(i, casefold=True)
                b = base64.b16decode(k, casefold=True)
                c = a[0] ^ S[b[0]]
                c = hex(c)[2:].zfill(2)
                # on va tester si c est une possibilité
                if is_candidat(c, octet_reference) and is_candidat(i, hex(k0[3])[2:].zfill(2)) and is_candidat(k, hex(k0[12])[2:].zfill(2)):
                    possibles.append((c, i, k))
                    c14.append(i)
                    c44.append(k)
                    cc14.append(c)

        # on va recuperer les plus probables
    ####colonnne 2###
    a11 = combinaison_z(hex(k0[4])[2:].zfill(2))
    a12 = combinaison_z(hex(k0[5])[2:].zfill(2))
    a13 = combinaison_z(hex(k0[6])[2:].zfill(2))
    a14 = combinaison_z(hex(k0[7])[2:].zfill(2))
    a11 = list(set(a11))
    a12 = list(set(a12))
    a13 = list(set(a13))
    a14 = list(set(a14))
    ####

    ####colonnne 2###
    b11 = combinaison_z(hex(k0[8])[2:].zfill(2))
    b12 = combinaison_z(hex(k0[9])[2:].zfill(2))
    b13 = combinaison_z(hex(k0[10])[2:].zfill(2))
    b14 = combinaison_z(hex(k0[11])[2:].zfill(2))

    b11 = list(set(b11))
    b12 = list(set(b12))
    b13 = list(set(b13))
    b14 = list(set(b14))
    ####

    # Les colonnes avec rotword
    c11 = list(set(c11))
    c12 = list(set(c12))
    c13 = list(set(c13))
    c14 = list(set(c14))

    c41 = list(set(c41))
    c42 = list(set(c42))
    c43 = list(set(c43))
    c44 = list(set(c44))
    col1 = forme_colonne(c11, c12, c13, c14)
    col2 = forme_colonne(a11, a12, a13, a14)
    col3 = forme_colonne(b11, b12, b13, b14)
    col4 = forme_colonne(c41, c42, c43, c44, 2)
    #print(col3)
    #on s'assure qu'il y a pas de doublons dans les colonnes
    col1 = list(set(col1))
    col2 = list(set(col2))
    col3 = list(set(col3))
    col4 = list(set(col4))
    
    print("1ere colonne " + str(len(col1)) + " possibilités")
    print("2eme colonne " + str(len(col2)) + " possibilités")
    print("3eme colonne " + str(len(col3)) + " possibilités")
    print("4eme colonne " + str(len(col4)) + " possibilités")
    #print(col3)
    # on lance la recherche dès qu'il y a une possibilité qui passe on renvoi la clé
    print("debut de la recherche")
    found = False
    for colonne1 in col1:
        if found:
            break
        for colonne2 in col2:
            if found:
                break
            for colonne3 in col3:
                if found:
                    break
                for colonne4 in col4:
                    new_key = colonne1 + colonne2 + colonne3 + colonne4
                    new_key_schedule = generate_key(new_key)
                    # on va tester si la combianison courante est la bonne
                    # si c'est le cas on arrete la recherche
                    if check_key(new_key_schedule, brut):
                        print("clés aes-128 corrrigées")
                        print(new_key_schedule)
                        found = True
                        break
                        #sys.exit()

    print("Recherche terminée")
    if not found:
        print("recherche echouée")


def temps(a, b, c):
    debut = time()
    attack(a, b, c)
    fin = time()
    return fin - debut


def main(argv):
    assert len(argv) == 1
    prob = int(argv[0])
    c = generate_key("9de87acdffecedfdfeffb7fedc7b81e6")  # les 11 clés aes-128
    cle_brout = brut_schedule(c, prob)  # les 11 clés broutées
    print("clés aes-128")
    print(c)
    print("clés aes-128 brutées")
    print(cle_brout)
    attack(cle_brout[0], cle_brout[1], cle_brout)

    """
    ###########PERFORMANCE############
    X = [1, 2, 3, 4]
    Y = [temps((brut_schedule(c, prob))[0], (brut_schedule(c, prob))[1], cle_brout) for prob in X]
    pl.plot(X, Y)
    pl.title("Performance en temps d'éxécution")
    pl.xlabel("Probabilité d'erreur")
    pl.ylabel("temps d'exécution")
    pl.show()
    #################################
    """


if __name__ == '__main__':
    if len(sys.argv) == 1:
        print("Passer la propabilité d'erreur en argument")
    else:
        main(sys.argv[1:])
