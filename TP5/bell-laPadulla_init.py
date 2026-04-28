"""
@author Yannick Chevalier
@date 2026
"""

class Contexts:
    contexts=set([]) # type set
    def __init__(self,ctxts=[]):
        self.contexts=set(ctxts)
    def add(self,ctxt):
        self.contexts.add(ctxt)
    def printContexts(self): # pour debug
        print(self.contexts)
    def compare(self,aContext):
        lowerOrEq=(self.contexts <= aContext.contexts)
        greaterOrEq=(self.contexts >= aContext.contexts)
        if lowerOrEq and greaterOrEq:
            return 0 # equal
        elif lowerOrEq:
            return -1
        elif greaterOrEq:
            return 1
        else:
            return None


class SecurityLevel:
    hierarchy=None
    contexts=None
    level=None
    def __init__(self,classification=hierarchy,ctxts=[],level=None):
        self.contexts=Contexts(ctxts)
        self.level=level
        self.hierarchy=classification
    def compare(self,aSecurityLevel):
        if not ( self.hierarchy == aSecurityLevel.hierarchy):
            return None
        ctxtcmp=self.contexts.compare(aSecurityLevel.contexts)
        levelcmp=self.hierarchy.compare(self.level,aSecurityLevel.level)
        # if either is incomparable, the result is incomparable
        if ctxtcmp is None or levelcmp is None:
            return None
        # if they are both non-zero but of a different sign, the result is None
        if ctxtcmp * levelcmp < 0:
            return None
        # if they agree (or equal)...
        return ctxtcmp+levelcmp
    def printLevel(self):
        print(f'hierarchy={self.hierarchy}, contexts={self.contexts.printContexts()}, level={self.level}')

class Classification:
    # classification is a dictionary that stores, for each security
    # level, all the levels strictly below it
    classification=None
    def __init__(self):
        self.classification=dict([])
    def addClassificationLevel(self,level,above=[]):
        # adds a level above those listed
        s= set(above)
        for lvl in above:
            s_level=self.classification.get(lvl)
            if s_level is not None:
                s=s.union(s_level)
        if level in s:
            raise Exception (f'Error, level {level} is already defined and below one of the levels it should be above')
        self.classification[level]=s
    def securityLevel(self,ctxts=[],level=None):
        if level not in self.classification:
            raise Exception(f'Level {level} is not known in this classification')
        return SecurityLevel(classification=self,ctxts=ctxts,level=level)
    def compare(self,level1,level2):
        if level1 == level2:
            return 0
        s1 = self.classification.get(level1)
        s2 = self.classification.get(level2)
        if s1 is None:
            raise Exception (f'Error, level {level1} is not defined in this classification')
        if s2 is None:
            raise Exception (f'Error, level {level2} is not defined in this classification')
        if level1 == level2:
            return 0
        if level1 in s2:
            return -1
        if level2 in s1:
            return 1
        return None


# --- mon code commence ici ---


# Un sujet = un processus. Il a un id, un groupe (comme uid/gid sous Unix),
# un niveau courant et un niveau max (pour la partie 5).
class Sujet:
    def __init__(self, sid, group, securityLevel, maxLevel=None, trusted=False):
        self.sid = sid
        self.group = group
        self.securityLevel = securityLevel
        # si on précise pas, le niveau max c'est le niveau de départ
        if maxLevel is not None:
            self.maxLevel = maxLevel
        else:
            self.maxLevel = securityLevel
        self.trusted = trusted
        # listes des objets ouverts (partie 4)
        self.openRead = set()
        self.openWrite = set()


# Un objet = un fichier
# trusted sert pour les programmes (cf. partie 3)
class Objet:
    def __init__(self, oid, owner, group, securityLevel, trusted=False):
        self.oid = oid
        self.owner = owner   # un sid
        self.group = group
        self.securityLevel = securityLevel
        self.trusted = trusted


class Controleur(Classification):
    def __init__(self):
        super().__init__()
        self.sujets = {}    # sid -> Sujet
        self.objets = {}    # oid -> Objet
        # matrice DAC : on indexe par (sid, oid) et on stocke un set de droits 'r','w','x'
        # (j'ai trouvé ça plus simple qu'une vraie matrice 2D)
        self.dac = {}

    # petites méthodes pour ajouter sujets/objets
    def addSujet(self, sujet):
        self.sujets[sujet.sid] = sujet

    def addObjet(self, objet):
        self.objets[objet.oid] = objet

    # donne des droits DAC à un sujet sur un objet
    def grant(self, sid, oid, perms):
        if (sid, oid) not in self.dac:
            self.dac[(sid, oid)] = set()
        self.dac[(sid, oid)].update(perms)

    # vérifie un droit DAC
    def dacCheck(self, sujet, objet, perm):
        # comme sous Unix, le proprio a tous les droits
        if objet.owner == sujet.sid:
            return True
        return perm in self.dac.get((sujet.sid, objet.oid), set())

    # ========== Partie 2 ==========

    def read(self, sid, oid):
        s = self.sujets[sid]
        o = self.objets[oid]
        # d'abord le DAC
        if not self.dacCheck(s, o, 'r'):
            return False
        # ensuite la sécurité simple : pas de read up
        # donc niveau du sujet doit être >= niveau de l'objet
        cmp = s.securityLevel.compare(o.securityLevel)
        if cmp is None or cmp < 0:
            return False
        # si tout va bien, on rajoute l'objet aux objets ouverts en lecture
        s.openRead.add(oid)
        return True

    def write(self, sid, oid):
        s = self.sujets[sid]
        o = self.objets[oid]
        if not self.dacCheck(s, o, 'w'):
            return False
        # sécurité * : pas de write down, donc niveau sujet <= niveau objet
        cmp = s.securityLevel.compare(o.securityLevel)
        if cmp is None or cmp > 0:
            return False
        s.openWrite.add(oid)
        return True

    # ========== Partie 3 ==========

    # le sujet sid exécute le programme progOid pour créer un nouveau sujet
    def execute(self, sid, progOid, newSid, newGroup, askedLevel, maxLevel=None):
        # on évite les doublons
        if newSid in self.sujets:
            return False
        s = self.sujets[sid]
        prog = self.objets[progOid]
        # il faut le droit x sur le programme
        if not self.dacCheck(s, prog, 'x'):
            return False
        if prog.trusted:
            # programme trusted : on prend le niveau demandé tel quel
            level = askedLevel
        else:
            # sinon il faut que le niveau demandé soit <= niveau du sujet appelant
            cmp = s.securityLevel.compare(askedLevel)
            if cmp is None or cmp < 0:
                return False
            level = askedLevel
        # on crée le nouveau sujet
        if maxLevel is None:
            maxLevel = s.maxLevel
        nouveau = Sujet(newSid, newGroup, level, maxLevel=maxLevel, trusted=prog.trusted)
        self.addSujet(nouveau)
        return True

    def kill(self, sid, targetSid):
        # cas particulier de l'énoncé : on peut toujours se kill soi-même
        if sid == targetSid:
            self.sujets.pop(sid, None)
            return True
        # sinon il faut que les deux existent
        if targetSid not in self.sujets or sid not in self.sujets:
            return False
        s = self.sujets[sid]
        t = self.sujets[targetSid]
        # j'ai pas trop su quoi mettre comme règle ici, je suis parti
        # sur "même groupe" ou "trusted", c'est proche de Unix
        if s.trusted or s.group == t.group:
            del self.sujets[targetSid]
            return True
        return False

    # ========== Partie 4 ==========

    # ferme un objet ouvert en lecture ou en écriture
    def close(self, sid, oid):
        s = self.sujets[sid]
        s.openRead.discard(oid)
        s.openWrite.discard(oid)
        return True

    # création d'un objet, le niveau est celui du sujet créateur (cf. énoncé)
    def touch(self, sid, oid, group=None, trusted=False):
        if oid in self.objets:
            return False     # déjà existant
        if sid not in self.sujets:
            return False
        s = self.sujets[sid]
        if group is None:
            group = s.group
        o = Objet(oid, owner=sid, group=group, securityLevel=s.securityLevel, trusted=trusted)
        self.addObjet(o)
        return True

    def rm(self, sid, oid):
        if oid not in self.objets:
            return False
        o = self.objets[oid]
        s = self.sujets.get(sid)
        # seul le proprio peut supprimer (sauf trusted)
        if s is None:
            return False
        if o.owner != sid and not s.trusted:
            return False
        # important : si on supprime l'objet faut nettoyer les listes openRead/openWrite
        # de tous les sujets, sinon on garde des références pourries
        for su in self.sujets.values():
            su.openRead.discard(oid)
            su.openWrite.discard(oid)
        # et nettoyer la matrice DAC aussi
        aSupprimer = [k for k in self.dac if k[1] == oid]
        for k in aSupprimer:
            del self.dac[k]
        del self.objets[oid]
        return True

    # change les droits DAC d'un sujet sur un objet (réservé au proprio)
    def chmod(self, sid, oid, targetSid, perms):
        if oid not in self.objets:
            return False
        o = self.objets[oid]
        if o.owner != sid:
            return False
        self.dac[(targetSid, oid)] = set(perms)
        return True

    # change le propriétaire d'un objet
    def chown(self, sid, oid, newOwnerSid):
        if oid not in self.objets:
            return False
        if newOwnerSid not in self.sujets:
            return False
        o = self.objets[oid]
        if o.owner != sid:
            return False
        o.owner = newOwnerSid
        return True

    # ========== Partie 5 ==========

    # un sujet non-trusted peut changer de niveau, mais sous conditions
    def changeLevel(self, sid, newLevel):
        if sid not in self.sujets:
            return False
        s = self.sujets[sid]
        # l'énoncé dit "les sujets qui ne sont pas trusted", donc je bloque les trusted
        if s.trusted:
            return False
        # 1ère condition : nouveau niveau <= niveau max du sujet
        cmpMax = s.maxLevel.compare(newLevel)
        if cmpMax is None or cmpMax < 0:
            return False
        # 2ème condition : il faut que ce soit cohérent avec les objets ouverts
        # pour les objets ouverts en lecture il faut newLevel >= niveau(objet)
        # (sinon on serait en read-up sur quelque chose qu'on lit déjà)
        for oid in s.openRead:
            obj = self.objets[oid]
            c = newLevel.compare(obj.securityLevel)
            if c is None or c < 0:
                return False
        # pour ceux ouverts en écriture c'est l'inverse : newLevel <= niveau(objet)
        for oid in s.openWrite:
            obj = self.objets[oid]
            c = newLevel.compare(obj.securityLevel)
            if c is None or c > 0:
                return False
        # tout est ok, on change le niveau
        s.securityLevel = newLevel
        return True
