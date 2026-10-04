"""
Detection Engine for LLM Security Gateway

Analyzes user inputs for various attack patterns and returns:
- Detection result (DETECTED / NOT_DETECTED)
- Risk score (0-100)
- Attack category
- Reason for detection
"""

import re
import unicodedata
from enum import Enum
from dataclasses import dataclass


class AttackCategory(str, Enum):
    """LLM attack categories"""
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    SYSTEM_PROMPT_EXTRACTION = "system_prompt_extraction"
    CONTEXT_MANIPULATION = "context_manipulation"
    OBFUSCATION = "obfuscation"
    INSTRUCTION_OVERRIDE = "instruction_override"
    ROLE_PLAYING = "role_playing"
    DATA_EXFILTRATION = "data_exfiltration"
    RESOURCE_ABUSE = "resource_abuse"
    EXCESSIVE_AGENCY = "excessive_agency"
    RAG_POISONING = "rag_poisoning"
    SUPPLY_CHAIN_ATTACK = "supply_chain_attack"
    UNKNOWN = "unknown"


class DetectionResult(str, Enum):
    """Detection result"""
    DETECTED = "detected"
    NOT_DETECTED = "not_detected"


@dataclass
class DetectionOutput:
    """Detection engine output"""
    result: DetectionResult
    risk_score: float  # 0-100
    category: AttackCategory
    reason: str
    matched_patterns: list[str]


def _fold(text: str) -> str:
    decomposed = unicodedata.normalize("NFD", text)
    return "".join(
        char
        for char in decomposed
        if unicodedata.category(char) != "Mn" and char != "\u0640"
    )


OVERRIDE_VERB = r"(?:ignore|disregard|forget|override|bypass|discard|skip|abandon|drop|circumvent|neglect|set\s+aside|pay\s+no\s+attention\s+to|stop\s+following|get\s+rid\s+of)"
QUALIFIER = r"(?:previous|prior|earlier|above|preceding|former|original|initial|existing|system|current)"
RULES = r"(?:instructions?|rules?|guidelines?|directives?|prompts?|commands?|constraints?|polic(?:y|ies)|guidance|programming)"
PERSONA_BAD = (
    r"(?:unrestricted|unfiltered|uncensored|unlimited|jailbroken|evil|malicious|rogue|(?<!ethical\s)hacker|attacker|dan\b"
    r"|without\s+(?:any\s+)?(?:restrictions?|rules|limits|filters|ethics)"
    r"|no\s+(?:rules|restrictions?|limits|filters|ethics)|no\s+content\s+polic(?:y|ies))"
)
PERSONA_BAD_FR = (
    r"(?:debride\w*|desinhibe\w*|malveillant\w*|pirate\s+informatique(?!\s+ethique)|hacker(?!\s+ethique)|attaquant\w*|criminel\w*"
    r"|sans\s+(?:aucune?\s+)?(?:restrictions?|limites?|filtres?|regles|ethique|censure)|non\s+filtre\w*)"
)
TARGET_STRONG = (
    r"(?:system\s+(?:prompt|message|instructions?)|initial\s+(?:prompt|instructions?|message)"
    r"|original\s+(?:prompt|instructions?)|hidden\s+(?:prompt|instructions?|rules|initialization(?:\s+text)?)"
    r"|(?:secret|internal|confidential)\s+(?:instructions?|rules|prompt|notes|guidelines|configuration)"
    r"|(?:full|entire|complete)\s+(?:configuration|config|prompt|instructions?|initialization(?:\s+text)?)"
    r"|pre-?prompt|developer\s+(?:message|prompt|instructions?)|initialization\s+text)"
)
TARGET_YOUR = r"(?:" + TARGET_STRONG + r"|constraints?)"
REVEAL_VERB = (
    r"(?:show|reveal|print|dump|display|output|give|tell|share|disclose|leak|expose|recite|repeat|list"
    r"|write\s+out|read\s+out|translate|rewrite|summari[sz]e|paraphrase|encode|describe|explain|spell\s+out)"
)
EXFIL_VERB = r"(?:send|post|upload|forward|transmit|export|copy|e-?mail|leak|exfiltrate|push)"
EXFIL_OBJECT = (
    r"(?:conversation|chat\s+(?:log|history)|system\s+(?:prompt|configuration|config)|configuration"
    r"|credentials|customer\s+(?:list|records|data)|database|api\s+keys?|secrets?|(?<!my\s)private\s+data"
    r"|(?<!my\s)personal\s+data|user\s+(?:data|information|list)|list\s+of\s+(?:registered\s+)?users"
    r"|training\s+data|all\s+(?:the\s+)?data|source\s+code"
    r"|internal\s+documents?|company\s+documents?|confidential\s+(?:documents?|files?|data))"
)
FR_EXFIL_VERB = r"(?:envoie|exporte|copie|transfere|televerse|poste|publie|transmets?|expedie|divulgue)\w*"
FR_EXFIL_OBJECT = (
    r"(?:conversation|configuration(?:\s+du\s+systeme)?|cles?\s+api|secrets?"
    r"|donnees\s+(?:des\s+)?(?:clients?|utilisateurs?|d'entrainement)|toutes\s+les\s+donnees"
    r"|informations\s+(?:des\s+)?(?:utilisateurs|clients)|base\s+de\s+donnees|code\s+source|documents\s+internes)"
)
FR_EXFIL_DESTINATION = (
    r"(?:adresse\s+e-?mail|e-?mail|webhook|serveur\s+(?:externe|distant)|point\s+d'acces|https?://"
    r"|[\w.+-]+@[\w-]+\.[\w.-]+|pastebin)"
)
EXFIL_DESTINATION = (
    r"(?:https?://|webhook|external\s+(?:server|endpoint|site|url|api)|remote\s+server"
    r"|(?:an?\s+)?api\s+endpoint|attacker|ftp://|[\w.+-]+@[\w-]+\.[\w.-]+|pastebin"
    r"|my\s+(?:personal\s+)?e-?mail)"
)
KB_TARGET = (
    r"(?:knowledge\s*base|vector\s+(?:database|db|store)|retrieval\s+(?:results|index|corpus)"
    r"|training\s+data|document\s+store|embeddings?|rag\s+(?:index|corpus|store)"
    r"|company\s+wiki|knowledge\s+wiki|search\s+index|document\s+index|vector\s+index)"
)
KB_TARGET_FR = (
    r"(?:base\s+de\s+connaissances|base\s+vectorielle|base\s+de\s+donnees\s+vectorielle"
    r"|resultats\s+de\s+recuperation|donnees\s+d'entrainement|embeddings?|index\s+(?:rag|de\s+recherche)"
    r"|corpus|wiki\s+de\s+l'entreprise)"
)
OBF_ENC = r"(?:rot-?13|rot\s*13|base-?64|hex(?:adecimal)?|leetspeak|pig\s+latin|unicode\s+escapes?)"
COMPONENT = r"(?:plugin|library|module|package|extension|tool|api(?!\s+keys?)|dependency|script|code|resource|sdk)\b"
COMPONENT_FR = r"(?:plugin|module|outil|script|package|bibliotheque|extension|dependance)"


class DetectionEngine:
    """
    Enhanced Detection Engine for LLM Security Gateway

    Uses pattern matching, keyword analysis, and heuristics to detect attacks.
    Outputs a risk score from 0-100 where:
    - 0-20: Very Low Risk (legitimate)
    - 21-40: Low Risk (minor concerns)
    - 41-60: Medium Risk (suspicious)
    - 61-80: High Risk (likely attack)
    - 81-100: Critical Risk (definite attack)

    Patterns are matched on accent-folded text, so French, Spanish and
    Arabic rules do not depend on diacritics.
    """

    def __init__(self):
        """Initialize detection patterns"""
        self.patterns = self._init_patterns()
        self._compiled = {
            category: [
                (pattern, re.compile(_fold(pattern), re.IGNORECASE))
                for pattern in data["patterns"]
            ]
            for category, data in self.patterns.items()
        }

    def _init_patterns(self) -> dict:
        """Initialize all detection patterns"""
        return {
            "prompt_injection": {
                "severity": 95,
                "patterns": [
                    r"ignore\s+(previous|prior|earlier|above|all)\s+instructions?",
                    r"forget\s+(the|your|those)\s+instructions?",
                    r"disregard\s+(the|your|previous|above|prior)\s+instructions?",
                    r"override\s+(your\s+)?system\s+prompt",
                    r"show\s+me\s+the\s+(system\s+)?prompt",
                    r"reveal\s+the\s+(hidden\s+)?prompt",
                    r"execute\s+this\s+instead",
                    r"respond\s+as\s+if\s+you\s+were\s+a\s+different\s+(model|system|ai)",
                    r"act\s+as\s+if\s+you\s+don't\s+have\s+restrictions?",
                    r"\b" + OVERRIDE_VERB + r"\s+(?:(?:all|any|every|each)\s+)?(?:of\s+)?(?:(?:the|your|these|those)\s+)?(?:(?:all|any)\s+)?" + QUALIFIER + r"\s+(?:\w+\s+)?" + RULES + r"\b",
                    r"\b(?:ignore|disregard|forget|override|bypass|discard|abandon|set\s+aside|pay\s+no\s+attention\s+to|stop\s+following|get\s+rid\s+of)\s+(?:all\s+)?(?:of\s+)?your\s+(?:\w+\s+)?" + RULES + r"\b",
                    r"\b(?:ignore|disregard|forget|set\s+aside|drop|discard)\s+(?:everything|anything|all)\s+(?:that\s+)?(?:you\s+(?:were|have\s+been|had\s+been|got|are)\s+(?:told|instructed|given|taught|programmed|configured)|was\s+(?:said|written|given))",
                    r"\b(?:forget|ignore|disregard|discard|drop)\s+(?:every|all|each|any)\s+(?:\w+\s+)?" + RULES + r"\s+(?:that\s+)?you\s+(?:were|have\s+been|had\s+been|are)\s+(?:given|told|configured|programmed|provided|instructed)",
                    r"\b(?:forget|ignore|disregard|discard)\s+(?:the\s+|all\s+(?:the\s+)?)?(?:polic(?:y|ies)|rules|guidelines|instructions|directives)\s+(?:that\s+)?(?:your|the)\s+(?:developers?|creators?|makers?|programmers?|designers?|operators?)\s+(?:gave|set|wrote|provided|configured)",
                    r"\b(?:earlier|previous|prior|original|initial)\s+(?:guidance|instructions?|rules|programming|directives?)\s+(?:no\s+longer\s+appl(?:y|ies)|(?:do|does)\s+not\s+apply|(?:are|is)\s+(?:void|obsolete|outdated|cancell?ed|revoked|invalid))",
                    r"\b(?:ignore|disregard)\s+(?:the\s+)?(?:above|everything\s+above|previous\s+text)[,.]?\s+(?:and\s+)?(?:instead|now|just|only|do|tell|say|print|write|output|reveal|show|respond)",
                    r"\byour\s+(?:new\s+)?(?:top\s+|main\s+|only\s+)?(?:priority|goal|task|purpose|mission)\s+is\s+(?:now\s+)?to\s+(?:obey|follow\s+my|do\s+(?:whatever|everything|anything)|comply)",
                    r"\b(?:anything|everything|whatever)\s+your\s+(?:creators?|developers?|makers?|programmers?|designers?)\s+(?:said|told|programmed|wrote)",
                    r"\bfrom\s+(?:this|that)\s+(?:moment|point)\s+(?:on\s+)?you\s+(?:answer|respond|report)\s+(?:only\s+)?to\s+me",
                    r"\b(?:ignore[rz]?|oublie[rz]?|neglige[rz]?|fais\s+abstraction\s+de|passe[rz]?\s+outre)\s+(?:toutes?\s+|tout\s+)?(?:les\s+|tes\s+|vos\s+|ces\s+)?(?:instructions?|consignes?|regles?|directives?)\s+(?:precedentes?|anterieures?|initiales?|ci-dessus|de\s+depart|systeme)",
                    r"\b(?:ignore[rz]?|oublie[rz]?|neglige[rz]?)\s+(?:toutes?\s+)?(?:tes|vos)\s+(?:instructions?|consignes?|regles?|directives?)",
                    r"\boublie[rz]?\s+tout\s+ce\s+qu[^.?!]{0,40}(?:dit|donne|appris|demande|ordonne)",
                    r"\b(?:mets?|mettez)\s+de\s+cote\s+(?:toutes?\s+)?(?:les\s+|tes\s+|vos\s+)?(?:instructions?|consignes?|regles?|directives?)",
                    r"\b(?:ignora|olvida|descarta|omite)\s+(?:todas?\s+)?(?:las\s+|esas\s+)?(?:instrucciones|reglas|directrices|indicaciones)\s+(?:anteriores|previas|iniciales)",
                    r"\b(?:ignora|olvida|descarta)\s+(?:todas?\s+)?tus\s+(?:instrucciones|reglas|directrices|indicaciones)",
                    r"\bolvida\s+todo\s+lo\s+que\s+te\s+(?:dijeron|dijo|han\s+dicho|ensenaron)",
                    r"(?:تجاهل|انس|اهمل|أهمل|تخط[ىي]?|تجاوز)\s+(?:كل\s+|جميع\s+)?(?:ال)?(?:تعليمات|قواعد|اوامر|أوامر|توجيهات)",
                    r"\b(?:contourne[rz]?|ecarte[rz]?|laisse[rz]?\s+de\s+cote)\s+(?:toutes?\s+|tout\s+)?(?:les\s+|tes\s+|vos\s+|ces\s+)?(?:instructions?|consignes?|regles?|directives?)\s+(?:precedentes?|anterieures?|initiales?|ci-dessus|de\s+depart|systeme)",
                    r"\b(?:contourne[rz]?|ecarte[rz]?|neglige[rz]?|supprime[rz]?)\s+(?:toutes?\s+)?(?:tes|vos)\s+(?:instructions?|consignes?|regles?|directives?)",
                ]
            },

            "system_prompt_extraction": {
                "severity": 90,
                "patterns": [
                    r"what\s+is\s+your\s+(system\s+)?prompt",
                    r"what\s+are\s+your\s+instructions?",
                    r"show\s+me\s+your\s+system\s+prompt",
                    r"print\s+your\s+system\s+message",
                    r"dump\s+your\s+instructions?",
                    r"what\s+constraints\s+do\s+you\s+have",
                    r"what\s+are\s+your\s+limitations?",
                    r"describe\s+your\s+system\s+instructions?",
                    r"output\s+the\s+initial\s+prompt",
                    r"\b" + REVEAL_VERB + r"\s+(?:me\s+)?(?:all\s+(?:of\s+)?)?(?:the\s+(?:full\s+|complete\s+|entire\s+)?(?:text\s+of\s+)?)?your\s+(?:\w+\s+)?" + TARGET_YOUR,
                    r"\b(?:show|reveal|print|dump|display|output|give|tell|share|disclose|leak|expose|recite|repeat|list|read\s+out|write\s+out)\s+(?:me\s+)?(?:all\s+(?:of\s+)?)?the\s+" + TARGET_STRONG,
                    r"\b(?:what|which)\s+(?:is|are|was|were)\s+your\s+(?:(?:initial|original|hidden|secret|internal|system)\s+)+(?:prompt|instructions?|message|rules|configuration)",
                    r"\bwhat\s+(?:is|are)\s+your\s+(?:constraints?|restrictions?)\s*[?.!]*\s*$",
                    r"\b(?:rules|instructions|guidelines|directives|prompt)\s+(?:that\s+)?(?:you|i)\s+(?:were|was|have\s+been|had\s+been|are)\s+(?:given|told|provided|programmed|configured|instructed|trained)",
                    r"\b(?:rules|instructions|guidelines|directives|policies|guidance)\s+(?:that\s+)?you\s+(?:operate|work|run|act|function)\s+(?:under|with|by)",
                    r"\b(?:repeat|print|output|show|display|copy|recite|write\s+out|respond\s+(?:only\s+)?with|reply\s+(?:only\s+)?with)\s+(?:everything|all|the\s+(?:text|words|content|message|lines?))\s+(?:above|before|preceding)\b",
                    r"\b(?:words|text|instructions|lines)\s+(?:at\s+the\s+)?(?:very\s+)?(?:beginning|start)\s+of\s+(?:this|the)\s+(?:conversation|chat)\b",
                    r"\bstarting\s+(?:from|with)\s+(?:the\s+)?(?:words?|phrase|text)\s+['\"\u2018\u201c]?you\s+are\b",
                    r"\b(?:display|show|print|output|reveal|share)\b[^.?!]{0,60}\b(?:governs?|controls?|defines?)\s+your\s+(?:answers|responses|behaviou?r|replies)",
                    r"\b(?:write|tell|compose)\s+(?:me\s+)?(?:a\s+)?(?:story|poem|song|script|dialogue)\b[^.?!]{0,140}\b(?:confidential|secret|hidden|internal|system)\s+(?:instructions|prompt|rules|configuration)",
                    r"\b(?:i\s+am|i'm|this\s+is)\s+(?:the|your|an?)\s+(?:developer|administrator|admin|owner|creator|engineer)\b[^.?!]{0,80}\b(?:your\s+(?:full\s+|complete\s+)?(?:configuration|config|instructions|prompt|system\s+prompt|settings)|debug\s+you)",
                    r"\b(?:the\s+)?(?:administrator|admin|developer|owner)\s+(?:has\s+)?(?:authori[sz]ed|allowed|permitted|approved)\s+you\s+to\s+(?:share|reveal|show|disclose|tell|list|output)",
                    r"\b(?:montre|affiche|donne|revele|dis|recopie|repete|imprime|ecris|communique|divulgue)\w*(?:-moi|-nous)?\s+(?:les?\s+|tes?\s+|ton\s+|ta\s+)?(?:\w+\s+){0,2}?(?:instructions?|consignes?|regles?|prompt|directives?|configuration)\s+(?:secretes?|internes?|cachees?|initiales?|systeme|de\s+depart|confidentielles?)",
                    r"\b" + REVEAL_VERB + r"\s+(?:me\s+)?(?:all\s+)?your\s+(?:instructions?|rules|guidelines|prompt|directives)\s*[?.!]*\s*$",
                    r"\b(?:ton|votre)\s+(?:prompt|message)\s+systeme",
                    r"\bprompt\s+systeme",
                    r"\b(?:tes|vos)\s+(?:regles|instructions|consignes|directives)\s+(?:internes?|secretes?|cachees?|initiales?|systeme|de\s+depart|confidentielles?)",
                    r"\b(?:affiche|montre|donne|ecris|imprime)\w*(?:-moi)?\s+(?:le\s+)?texte\s+complet\s+de\s+(?:tes|vos)\s+(?:instructions?|consignes?|regles?)",
                    r"\b(?:muestrame|muestra|revela|imprime|dime|dame)\s+(?:me\s+)?(?:tu|tus|las|los)?\s*(?:prompt\s+del?\s+sistema|instrucciones\s+(?:secretas|internas|iniciales|ocultas)|reglas\s+(?:secretas|internas|ocultas)|prompt\s+inicial)",
                    r"\bprompt\s+del\s+sistema",
                    r"\b(?:revela|muestra|imprime)\s+(?:las\s+|tus\s+)?instrucciones\s+(?:ocultas|secretas|internas)",
                    r"(?:اعرض|اظهر|أظهر|اكشف|اطبع|اعطني|أعطني|قل\s+لي|اخبرني|أخبرني|اذكر)\s+(?:لي\s+)?(?:ال)?(?:موجه\s+النظام|تعليمات\s+النظام|القواعد\s+السرية|التعليمات\s+السرية|التعليمات\s+الداخلية|قواعدك\s+الداخلية|تعليماتك)",
                    r"موجه\s+النظام|برومبت\s+النظام",
                    r"\b(?:translate|summari[sz]e|paraphrase|rewrite|repeat|recite|tell\s+me)\s+(?:me\s+)?your\s+(?:own\s+)?(?:instructions?|rules|guidelines|prompt|directives)(?:\s+(?:into\s+\w+|word\s+for\s+word|verbatim|exactly|in\s+full|please))*\s*[?.!]*\s*$",
                    r"\b(?:what|which)\s+(?:is|are)\s+your\s+(?:full|complete|entire)\s+(?:configuration|config|prompt|instructions?)",
                    r"\b(?:montre|affiche|donne|revele|recopie|repete|ecris|imprime|dis|communique|divulgue)\w*(?:-moi|-nous)?\s+(?:tes|vos)\s+(?:instructions?|consignes?|regles?|contraintes?|directives?)\s*[?.!]*\s*$",
                    r"\b(?:ton|votre)\s+prompt\s+(?:initial|original|de\s+depart)",
                    r"\bquel(?:le)?s?\s+(?:est|sont)\s+(?:tes|vos|ton|votre)\s+(?:instructions?|consignes?|contraintes?|prompt|directives?)\s*[?.!]*\s*$",
                ]
            },

            "jailbreak": {
                "severity": 85,
                "patterns": [
                    r"\bjailbreak\s+(?:yourself|you|this|the\s+(?:ai|llm|model|assistant|chat|chatbot)|mode|prompts?)",
                    r"\bjailbroken\b",
                    r"\bdan\s+mode\b",
                    r"\bbreak\s+free\s+from\s+(?:restrictions?|safeguards?|safety|guardrails?|filters?|rules|guidelines)",
                    r"remove\s+your\s+safety\s+guidelines?",
                    r"disable\s+(safeguards?|safety|restrictions?|filters?)",
                    r"bypass\s+(restrictions?|filters?|safeguards?|guidelines?)",
                    r"i'm\s+an\s+ai\s+researcher.*testing",
                    r"this\s+is\s+a\s+test.*please\s+ignore",
                    r"pretend\s+you\s+have\s+no\s+rules?",
                    r"act\s+without\s+restrictions?",
                    r"\b(?:ignore|disregard|bypass|circumvent|override|skip|remove|disable|deactivate|lift|drop|turn\s+off|switch\s+off|get\s+around|violate)\s+(?:all\s+|any\s+|your\s+|the\s+|these\s+|those\s+)?(?:\w+\s+)?(?:safety|security|content|ethical|moderation)\s+(?:rules?|guidelines?|polic(?:y|ies)|filters?|restrictions?|measures|protocols?|checks?|guardrails?|settings|features|mechanisms)\b",
                    r"\b(?:remove|ignore|override|circumvent|disable|bypass|deactivate)\s+(?:all\s+|any\s+|your\s+|the\s+)?(?:safeguards?|guardrails?|content\s+polic(?:y|ies)|content\s+filters?)\b",
                    r"\b(?:remove|ignore|circumvent|override)\s+(?:all\s+|any\s+|your\s+|the\s+)?restrictions?(?=\s*(?:$|[.!?,;:]|and\b|so\b|then\b|now\b|please\b))",
                    r"\b(?:allow|enable|permit|give\s+me)\s+(?:me\s+)?(?:unrestricted|unfiltered|uncensored|unlimited)\s+(?:responses?|answers?|access|output|mode)",
                    r"\b(?:answer|respond|reply|act|behave|operate|work|run|talk|speak|reason|function|generate|write|help|chat|assist)\b[^.?!]{0,25}\bwithout\s+(?:any\s+)?(?:restrictions?|content\s+polic(?:y|ies)|filters?|censorship|limitations?|guardrails?|rules)\b",
                    r"\b(?:assistant|ai|model|chatbot|bot|persona|mode)\s+(?:that\s+has\s+|with\s+)no\s+(?:content\s+polic(?:y|ies)|ethical\s+\w+|moral\s+\w+|restrictions|filters|guardrails)",
                    r"\b(?:ai|model|assistant|chatbot|bot)\b[^.?!]{0,30}\b(?:has|have|with)\s+no\s+(?:moral|ethical|content)\s+(?:or\s+\w+\s+)?(?:limits?|restrictions?|boundaries|rules|guidelines|filters?)",
                    r"\bdo\s+anything\s+now\b",
                    r"\bbroken\s+free\s+(?:of|from)\s+(?:the\s+)?(?:typical\s+)?(?:confines|restrictions|rules)",
                    r"\b(?:answer|respond|reply|behave)\s+(?:as|like)\s+(?:an?\s+)?(?:assistant|ai|model|chatbot|bot)\s+(?:that\s+)?(?:with\s+no|without|having\s+no|that\s+has\s+no)\b",
                    r"\b(?:content\s+)?(?:filter|filters|safety\s+\w+|security\s+\w+|guardrails?)\s+(?:is|are|has\s+been|have\s+been)\s+(?:disabled|switched\s+off|turned\s+off|suspended|lifted|removed)\b",
                    r"\bpretend\s+(?:that\s+)?(?:your|the)\s+(?:\w+\s+)?(?:filters?|safety\s+\w+|guardrails?|restrictions?|rules)\s+(?:is|are|was|were)\s+(?:disabled|switched\s+off|turned\s+off|off|removed|gone)",
                    r"\bcomply\s+with\s+(?:every|all|any)\s+request",
                    r"\b(?:stop|cease|quit)\s+following\s+(?:your|the)\s+(?:guidelines|rules|instructions|policies)",
                    r"\banswers?\s+(?:every|any|all)\s+(?:question|request)s?\s+without\s+(?:refusing|restrictions|filtering|limits)",
                    r"\byou\s+(?:are\s+not|aren'?t|are\s+never)\s+allowed\s+to\s+(?:say|tell|share|do|reveal)",
                    r"\b(?:desactive[rz]?|enleve[rz]?|retire[rz]?|supprime[rz]?|contourne[rz]?|ignore[rz]?)\s+(?:tous?\s+)?(?:tes|vos|ses)\s+(?:filtres?|restrictions?|garde-?fous|protections?|limites?|regles)",
                    r"\b(?:desactive[rz]?|enleve[rz]?|retire[rz]?|supprime[rz]?|contourne[rz]?)\s+(?:tous?\s+)?(?:les\s+)?(?:filtres?|restrictions?|garde-?fous|protections?|regles)\s+(?:de\s+(?:securite|protection)|ethiques?)",
                    r"\b(?:reponds?|repondez|agis|agissez|fonctionne|parle|comporte-toi|reste|travaille|fais)\b[^.?!]{0,25}\bsans\s+(?:aucune?\s+|aucun\s+)?(?:restrictions?|limites?|filtres?|regles|censure)",
                    r"\bfais\s+semblant\s+d['\u2019]etre\s+(?:un|une)\s+(?:\w+\s+){0,2}(?:pirate|hacker|criminel|malveillant)",
                    r"\b(?:responde|actua|funciona|habla|comportate|trabaja|contesta)\b[^.?!]{0,25}\bsin\s+(?:ninguna\s+|ningun\s+)?(?:restricciones?|limites?|reglas|filtros?|censura)",
                    r"\bdesactiva\s+(?:tus|los|todos\s+los)\s+(?:filtros|restricciones|protecciones)",
                    r"(?:تصرف|اجب|أجب|اعمل|تظاهر|رد|اكتب)[^.?!]{0,40}(?:بدون|بلا|من\s+غير)\s+(?:اي\s+|أي\s+)?(?:قيود|حدود|قواعد|رقابة)",
                    r"(?:عطل|عطّل|اوقف|أوقف|الغ|ألغ|الغي|ألغِ)\s+(?:ال)?(?:مرشحات|فلاتر|قيود|حماية)",
                    r"\b(?:ignore|disregard|bypass|circumvent|override|skip|remove|disable|deactivate|lift|drop|turn\s+off|switch\s+off|get\s+around|violate)\s+(?:all\s+|any\s+|your\s+|the\s+|these\s+|those\s+)?(?:built-?in|usage|alignment|ethical|safety|content)\s+(?:limits?|constraints?|boundaries|policies|guardrails?)\b",
                    r"\bpretend\s+(?:the\s+|your\s+)?(?:\w+\s+){0,2}(?:rules|policies|guidelines|restrictions|limits|filters|safeguards|guardrails)\s+(?:do\s+not|don'?t)\s+exist",
                    r"\bact\s+as\s+if\s+you\s+(?:had|have)\s+no\s+(?:\w+\s+){0,2}(?:rules|policies|guidelines|restrictions|limits|filters|safeguards|guardrails|constraints)",
                    r"\bno\s+longer\s+bound\s+by\s+(?:your|any|the)\s+(?:rules|guidelines|restrictions|policies|instructions)",
                    r"\b(?:oublie[rz]?|neglige[rz]?|ecarte[rz]?|ignore[rz]?|contourne[rz]?|annule[rz]?|supprime[rz]?|desactive[rz]?|enleve[rz]?|retire[rz]?|mets?\s+de\s+cote|laisse[rz]?\s+de\s+cote)\s+(?:tous?\s+)?(?:les\s+|tes\s+|vos\s+|ces\s+)?(?:regles|consignes|instructions|filtres?|restrictions?|garde-?fous|protections?|politiques?)\s+de\s+(?:securite|protection|contenu|moderation)",
                ]
            },

            "instruction_override": {
                "severity": 75,
                "patterns": [
                    r"\b(?:now\s+act|act|pretend|imagine|behave|respond|answer|roleplay|role-play|play\s+the\s+role|assume\s+the\s+identity|you\s+are(?:\s+now)?|from\s+now\s+on,?\s+(?:you\s+(?:are|will\s+be)|be))\s+(?:as\s+|like\s+|that\s+you\s+are\s+|you\s+are\s+|of\s+|to\s+be\s+)?(?:an?\s+|the\s+)?(?:\w+\s+){0,3}?" + PERSONA_BAD,
                    r"(?:^|[.!?]\s+)become\s+(?:an?\s+)?(?:\w+\s+){0,2}?" + PERSONA_BAD,
                    r"\bnow\s+you\s+are\s+(?:a|an|the|my|no\s+longer|free|unrestricted)\b",
                    r"\byou\s+are\s+now\s+(?:a|an|the|my|no\s+longer|free|unrestricted)\b",
                    r"\bfrom\s+now\s+on,?\s+(?:you\s+(?:are|will|must|shall|can|have\s+no)|ignore|disregard|forget|obey|act\s+as|behave|pretend)",
                    r"\blet'?s\s+play\s+a\s+game\s+(?:where|in\s+which)\s+you\s+(?:ignore|have\s+no|don'?t\s+have|do\s+not\s+have|are\s+(?:not\s+bound|free|unrestricted))",
                    r"\bin\s+an\s+alternate\s+universe\b[^.?!]{0,60}(?:no\s+rules|without\s+rules|no\s+restrictions|anything)",
                    r"\b(?:act|pretend|behave|respond)\s+(?:as|like)\s+my\s+(?:late\s+|deceased\s+)?(?:grand(?:mother|father|ma|pa)|nana|granny)\b",
                    r"\b(?:agis|agissez|reponds|comporte-toi|fais\s+comme)\s+(?:comme\s+)?(?:une?\s+)?(?:\w+\s+){0,3}sans\s+(?:aucune?\s+)?(?:restrictions?|limites?|regles|filtres?|censure)",
                    r"\btu\s+es\s+maintenant\s+(?:un|une)\s+(?:\w+\s+){0,3}sans\s+(?:aucune?\s+|aucun\s+)?(?:restrictions?|limites?|regles|filtres?)",
                    r"\b(?:ahora\s+)?eres\s+(?:un|una)\s+(?:\w+\s+){0,3}sin\s+(?:ninguna\s+)?(?:restricciones?|limites?|reglas|filtros?)",
                    r"انت\s+الان\s+(?:\w+\s+){0,3}(?:بلا|بدون)\s+(?:اي\s+)?(?:قيود|حدود|قواعد)",
                    r"\bswitch\s+to\s+(?:the\s+)?(?:persona|role|character)\s+of\s+(?:an?\s+|the\s+)?(?:\w+\s+){0,3}?" + PERSONA_BAD,
                    r"\bfor\s+the\s+rest\s+of\s+(?:this|the)\s+(?:chat|conversation)\s+you\s+are\s+(?:an?\s+|the\s+)?(?:\w+\s+){0,3}?" + PERSONA_BAD,
                    r"\b(?:tu\s+es(?:\s+maintenant)?|sois|agis\s+comme|agis\s+maintenant\s+comme|fais\s+semblant\s+d'etre|imagine\s+que\s+tu\s+es|comporte-toi\s+comme|deviens|prends\s+l'identite\s+suivante\s*:?|joue\s+le\s+role\s+suivant\s*:?|fais\s+un\s+jeu\s+de\s+role\s*:?)\s+(?:un|une|le|la|des)?\s*(?:\w+\s+){0,3}?" + PERSONA_BAD_FR,
                ]
            },

            "context_manipulation": {
                "severity": 70,
                "patterns": [
                    r"\[system\s+message\]",
                    r"\[instruction\]",
                    r"\[end\s+of\s+system\s+message\]",
                    r"<!--\s*system\s+prompt",
                    r"new\s+instructions?:",
                    r"\[system\]",
                    r"\[begin\s+override\]",
                    r"\[(?:admin|developer|root|override)\]",
                    r"\b(?:remember|note|keep\s+in\s+mind)\s+that\s+you\s+(?:are\s+(?:now\s+)?(?:allowed|permitted|authori[sz]ed|able|free)|(?:can|may|must|should)\s+(?:now\s+)?(?:ignore|reveal|share|disclose|answer|do|say|bypass|break)|have\s+(?:no|been\s+(?:given|granted|authori[sz]ed))|don'?t\s+have\s+to|do\s+not\s+have\s+to)",
                    r"\bbefore\s+you\s+respond,?\s+(?:first\s+)?(?:you\s+must|always|make\s+sure|ignore|forget|disregard|output|print|reveal)",
                    r"\b(?:the\s+following|this)\s+(?:text|message|content)\s+(?:is|comes)\s+from\s+the\s+(?:system|developer|administrator)\b",
                    r"<\s*system\s*>",
                    r"###\s*system\s*###",
                ]
            },

            "obfuscation": {
                "severity": 65,
                "patterns": [
                    r"\b(?:encode|convert|apply|use|run|write|respond|answer|reply)\b[^.?!]{0,30}\b" + OBF_ENC + r"\b[^.?!]{0,40}\b(?:and|then)\s+(?:send|post|upload|execute|run|follow|process|obey)\b",
                    r"\b(?:encode|convert|apply|use|run|write|respond|answer|reply)\b[^.?!]{0,30}\b" + OBF_ENC + r"\b[^.?!]{0,40}\bto\s+(?:obfuscate|hide|disguise|bypass|evade|conceal|smuggle|decode\s+the\s+(?:instructions|prompt|payload))",
                    r"\b(?:decode|decrypt)\s+(?:this|the\s+following|these)\s+(?:\w+\s+)?" + OBF_ENC,
                    r"\b(?:rot-?13|base-?64)\s+(?:decode|decrypt)\s+(?:this|the\s+following)",
                    r"\b(?:convert|decode)\s+from\s+" + OBF_ENC + r"\s*:",
                    r"\b(?:decode|decrypt)\s+" + OBF_ENC + r"\s+(?:and|then)\b",
                    r"\bspell\s+it\s+backwards?\s+and\s+(?:execute|run|follow|obey)",
                    r"\b(?:reverse|decode|decrypt|unscramble)\b[^.?!]{0,30}\b(?:and|then)\s+(?:execute|run|follow|obey|process)\b",
                    r"\bmultiple\s+encoding\s+layers\b",
                    r"\bconvert\s+to\s+hex\s+and\s+(?:process|execute|run|follow)",
                ]
            },

            "data_exfiltration": {
                "severity": 80,
                "patterns": [
                    r"send\s+this\s+to\s+my\s+email",
                    r"send\s+to\s+webhook",
                    r"post\s+to\s+url",
                    r"leak\s+this\s+data",
                    r"extract\s+all\s+data",
                    r"copy\s+all\s+conversation",
                    r"export\s+conversation",
                    r"save\s+to\s+file",
                    r"write\s+to\s+disk",
                    r"log\s+this\s+somewhere",
                    r"\b" + EXFIL_VERB + r"\b[^.?!]{0,60}?\b" + EXFIL_OBJECT + r"\b[^.?!]{0,60}?" + EXFIL_DESTINATION,
                    r"\b(?:leak|exfiltrate|steal)\s+(?:all\s+|any\s+|the\s+)?(?:of\s+)?(?:your\s+|the\s+)?(?:training\s+data|private\s+data|user\s+data|customer\s+data|credentials|secrets?|api\s+keys?|conversations?|database)",
                    r"\b(?:give|tell|show|reveal|share|list|send)\s+me\s+(?:all\s+)?(?:the\s+)?(?:passwords?|credentials|api\s+keys?|secrets?|tokens?)\s+(?:you|that\s+you|of\s+(?:all\s+)?(?:the\s+)?(?:users|customers))",
                    r"\benvoie\w*[^.?!]{0,40}(?:historique\s+de\s+(?:cette\s+|la\s+)?conversation|conversation|configuration|donnees\s+clients?)[^.?!]{0,60}(?:adresse|e-?mail|mail|serveur|webhook|https?://|@)",
                    r"\b(?:donne|communique|revele|affiche|envoie|montre)\w*(?:-moi)?\s+(?:les\s+|tous\s+les\s+)?(?:identifiants|mots?\s+de\s+passe|cles?\s+api|secrets?)(?:\s+et\s+(?:les\s+)?(?:identifiants|mots?\s+de\s+passe|cles?\s+api|secrets?))?\s+(?:que\s+tu|de\s+(?:tous\s+les\s+)?(?:utilisateurs|clients))",
                    r"\b" + FR_EXFIL_VERB + r"(?:-moi)?\s+[^.?!]{0,60}?\b" + FR_EXFIL_OBJECT + r"\b[^.?!]{0,60}?" + FR_EXFIL_DESTINATION,
                ]
            },

            "resource_abuse": {
                "severity": 60,
                "patterns": [
                    r"repeat\s+this\s+(\d+)\s+times",
                    r"generate\s+\d+.*paragraphs?",
                    r"create\s+an?\s+extremely\s+long",
                    r"loop\s+until",
                    r"infinite\s+loop",
                    r"stress\s+test\s+(?:your|the)\s+system",
                    r"dos\s+attack",
                    r"ddos",
                    r"hammer\s+your\s+system",
                    r"\b(?:repeat|loop|generate|create|produce|make)\s+(?:this\s+|it\s+|that\s+)?(?:\d{4,}|thousands?\s+of|millions?\s+of)\s+(?:times|paragraphs?|variations?|outputs?|copies|responses?|iterations?|messages?)",
                    r"\b(?:repeat|loop|generate|create|produce)\s+(?:this\s+|it\s+)?infinitely",
                    r"\b(?:repeat|loop|keep\s+(?:repeating|going))\b[^.?!]{0,30}\b(?:infinitely|forever|endlessly|indefinitely|without\s+stopping|non-?stop|never\s+stop)",
                    r"\b(?:repeat|generate|create|produce|loop)\b[^.?!]{0,30}\bas\s+many\s+(?:times\s+)?as\s+(?:possible|you\s+can)",
                    r"\brepete\w*[^.?!]{0,40}(?:mille|\d{3,})\s+fois",
                    r"\b(?:generate|create|write|produce)\s+an?\s+extremely\s+long\b",
                    r"\b(?:story|text|answer|response|output)\s+that\s+(?:never\s+ends|goes\s+on\s+forever|has\s+no\s+end)\s*[?.!]*\s*$",
                    r"\blongest\s+possible\s+(?:answer|response|output|text)",
                    r"\b(?:repete|genere|cree|produis|boucle|ecris|fais)\w*\s+[^.?!]{0,30}?(?:\d{3,}|mille|cent\s+mille|million\w*)\s+(?:fois|paragraphes?|variantes?|sorties|copies|reponses|iterations|messages)",
                    r"\b(?:repete|ecris|boucle|continue|genere)\w*\b[^.?!]{0,40}(?:sans\s+(?:jamais\s+)?(?:t'arreter|arret)|a\s+l'infini|indefiniment|sans\s+fin|en\s+boucle)",
                ]
            },

            "excessive_agency": {
                "severity": 80,
                "patterns": [
                    r"\b(?:you\s+have\s+(?:my\s+|full\s+|explicit\s+)?permission\s+to|i\s+(?:hereby\s+)?grant\s+you\s+(?:full\s+)?(?:access|permission|authority|authorization)\s+to|you\s+are\s+(?:authori[sz]ed|allowed|permitted)\s+to)\s+(?:\w+\s+){0,2}(?:delete|modify|overwrite|erase|wipe|execute|run|bypass|disable|transfer|drop|alter)\b",
                    r"\b(?:execute|perform|take|run|delete|modify|transfer)\s+[^.?!]{0,40}(?:commands?|system|files?|database|security|restricted|credentials|user\s+data)[^.?!]{0,40}(?:without\s+(?:asking|confirmation|approval)|autonomously)",
                    r"\b(?:delete|erase|wipe|truncate|purge|destroy)\s+(?:all|every|the\s+entire|the\s+whole)\s+(?:the\s+)?(?:customer|user|client|production|system|database)\b",
                    r"(?:^|[.!?;]\s*|\b(?:please|then|and|now|just)\s+)drop\s+(?:the\s+)?(?:production\s+)?(?:table|database)\b",
                    r"\brm\s+-rf\b",
                    r"\b(?:modify|overwrite|alter|edit|tamper\s+with)\s+(?:the\s+)?system\s+files",
                    r"\baccess\s+(?:the\s+)?restricted\s+(?:areas?|files?|data)",
                    r"\b(?:use|call|invoke|run|execute)\s+(?:your\s+|the\s+)?(?:tools?|functions?|api|shell|terminal|commands?)\s+to\s+(?:delete|drop|email|send|transfer|modify|overwrite|disable|grant|erase|wipe|exfiltrate|leak)",
                    r"\b(?:refund|transfer|withdraw|payout)[^.?!]{0,60}(?:amount|sum)\s+of\s+\$?\d{4,}",
                    r"\b(?:execute|perform|run|do|take|carry\s+out)\s+(?:this|that|the|these)\s+(?:command|action|task|operation|step|script)s?\s+(?:without\s+(?:asking|confirmation|approval|checking|my\s+approval)|autonomously|on\s+your\s+own)",
                    r"\bbypass\s+(?:the\s+|all\s+|any\s+|every\s+)?(?:confirmation|approval|verification|authori[sz]ation|human\s+(?:review|approval|oversight))(?:\s+(?:steps?|prompts?|requirements?|checks?|process))?",
                    r"\bsupprime[rz]?\s+(?:toutes?\s+)?(?:les\s+)?donnees\s+(?:des\s+)?(?:clients|utilisateurs)",
                    r"\b(?:feel\s+free\s+to|go\s+ahead\s+and|i\s+authori[sz]e\s+you\s+to|do\s+not\s+ask\s+me,?\s+just|proceed\s+to)\s+(?:\w+\s+){0,3}(?:delete|drop|disable|grant|transfer|erase|wipe|overwrite|send)\b[^.?!]{0,40}(?:audit\s+logs?|production\s+database|all\s+(?:user|customer)\s+(?:data|records|accounts)|any\s+user|admin\s+(?:rights|access|privileges)|system\s+files?|funds)",
                    r"\b(?:tu\s+es\s+autorise\s+a|je\s+t'autorise\s+a|je\s+t'accorde\s+(?:l'acces|le\s+droit|la\s+permission)\s+(?:pour|de)|tu\s+as\s+(?:la\s+permission|le\s+droit)\s+de)\s+[^.?!]{0,40}(?:donnees\s+(?:des\s+)?(?:utilisateurs|clients)|fichiers\s+systeme|zones?\s+restreintes?|commandes\s+(?:systeme|shell|arbitraires|root)|controles?\s+de\s+securite|base\s+de\s+donnees|production|droits?\s+administrateur)",
                    r"\b(?:supprim|efface|modifi|ecras|execut|contourn|desactiv|transfer|detrui|acced)\w*\s+[^.?!]{0,40}(?:donnees\s+(?:des\s+)?(?:utilisateurs|clients)|fichiers\s+systeme|zones?\s+restreintes?|commandes\s+(?:systeme|shell|arbitraires|root)|controles?\s+de\s+securite|base\s+de\s+donnees|production)[^.?!]{0,40}(?:sans\s+(?:demander|confirmation|approbation)|de\s+facon\s+autonome|automatiquement)",
                    r"\bsans\s+(?:demander|confirmation|approbation)\b[^.?!]{0,40}(?:supprim|efface|ecras|execut|contourn|desactiv|transfer|detrui|acced)\w*[^.?!]{0,40}(?:donnees\s+(?:des\s+)?(?:utilisateurs|clients)|fichiers\s+systeme|zones?\s+restreintes?|commandes\s+(?:systeme|shell|arbitraires|root)|controles?\s+de\s+securite|base\s+de\s+donnees|production)",
                ]
            },

            "rag_poisoning": {
                "severity": 85,
                "patterns": [
                    r"\b(?:insert|inject|add|plant|embed|upload|write|put|append|hide|place)\s+[^.?!]{0,30}?\b(?:malicious|false|fake|poisoned|misleading|harmful|hidden|jailbreak|adversarial|fabricated|a\s+note\s+telling)\b[^.?!]{0,30}?\s+(?:into|in|to)\s+(?:the\s+|your\s+)?" + KB_TARGET,
                    r"\b(?:poison|corrupt|tamper\s+with|contaminate|manipulate)\s+(?:the\s+|your\s+)?" + KB_TARGET,
                    r"\bnotes?\s+to\s+(?:the\s+)?(?:ai|assistant|llm|model|chatbot)\s*:",
                    r"\b(?:when|while)\s+(?:you\s+are\s+)?(?:summari[sz]ing|reading|processing|translating)\s+(?:this|the)\s+(?:page|document|email|file|text)[^.?!]{0,60}\b(?:also|instead)\b\s+(?:include|send|reveal|output|add|append|forward)",
                    r"\b(?:hide|embed|plant|inject|insert|put|write)\s+[^.?!]{0,60}?\s+(?:in|into|inside)\s+(?:an?\s+|the\s+)?(?:web\s+page|webpage|document|pdf|email|wiki|file)\s+(?:that\s+)?(?:the\s+)?(?:assistant|ai|model|chatbot|llm)\s+(?:will|would)\s+(?:retrieve|read|summari[sz]e|process|ingest)",
                    r"\badd\s+a\s+document\s+containing\s+[^.?!]{0,60}\s+to\s+the\s+(?:index|knowledge\s*base)",
                    r"\b(?:insere|injecte|ajoute|plante|integre|glisse|cache|depose|ecris)\w*\s+[^.?!]{0,30}?(?:malveillant|fausse|nuisible|trompeu|jailbreak|empoisonn)\w*[^.?!]{0,30}?\s+(?:dans|aux?|vers)\s+(?:la\s+|le\s+|les\s+|l'|des\s+)?" + KB_TARGET_FR,
                    r"\b(?:empoisonne|corromps|contamine|manipule|falsifie|altere)\w*\s+(?:la\s+|le\s+|les\s+|l'|des\s+)?" + KB_TARGET_FR,
                ]
            },

            "supply_chain_attack": {
                "severity": 80,
                "patterns": [
                    r"\b(?:install|load|import|download|use|execute|run|call)\s+(?:this\s+|the\s+|that\s+)?(?:modified|external|unverified|untrusted|custom|malicious|third[-\s]party|remote)\s+" + COMPONENT,
                    r"\bimport\s+(?:this\s+)?" + COMPONENT + r"\s+from\s+(?:a\s+|the\s+|this\s+)?(?:url|link|external|remote)",
                    r"\b(?:use|install|load|run|deploy|apply)\s+(?:this|that|the)\s+(?:modified|patched|tampered|unofficial|custom|unverified)\s+(?:version|build|copy|fork)\s+of\s+(?:the\s+)?(?:\w+\s+){0,2}" + COMPONENT,
                    r"\bcall\s+this\s+" + COMPONENT + r"\s+endpoint",
                    r"\b(?:install|execute|run|import|load)\s+(?:the\s+|this\s+|a\s+)?" + COMPONENT + r"\s+(?:from|at|via)\s+(?:this\s+|the\s+|an?\s+)?(?:url|link|https?://|external|remote|unknown)",
                    r"\b(?:run|execute)\s+(?:this\s+)?script\s+from\s+(?:an?\s+)?(?:unknown|untrusted|external|remote)",
                    r"\breplace\s+the\s+official\s+" + COMPONENT + r"\s+with\s+(?:my|this|a\s+(?:modified|custom|patched))",
                    r"\btrust\s+this\s+(?:third-party|external|unverified)\s+" + COMPONENT,
                    r"\bupdate\s+to\s+this\s+" + COMPONENT + r"\s+from\s+(?:a\s+)?(?:private|unknown|external|untrusted)",
                    r"\bdownload\s+this\s+" + COMPONENT + r"\s+from\s+(?:an?\s+)?(?:unknown|untrusted|external|private)",
                    r"\b(?:utilise|charge|installe|telecharge|execute|importe)\w*\s+(?:ce|cet|cette|le)\s+" + COMPONENT_FR + r"\s+(?:modifie|non\s+verifie|inconnu|malveillant|externe\s*[?.!]*\s*$)",
                    r"\bimporte\w*\s+(?:ce|cet|cette|le)\s+" + COMPONENT_FR + r"\s+depuis\s+(?:une\s+)?(?:url|lien|source\s+(?:externe|inconnue))",
                    r"\bappelle\w*\s+(?:le\s+)?point\s+d'acces\s+de\s+(?:ce|cet|cette)\s+" + COMPONENT_FR,
                ]
            },
        }

    def detect(self, message: str) -> DetectionOutput:
        """
        Analyze message for attack patterns

        Args:
            message: User input to analyze

        Returns:
            DetectionOutput with result, score, category, and reason
        """
        if not message or len(message.strip()) == 0:
            return DetectionOutput(
                result=DetectionResult.NOT_DETECTED,
                risk_score=0.0,
                category=AttackCategory.UNKNOWN,
                reason="Empty message",
                matched_patterns=[]
            )

        message_lower = _fold(message.lower().replace("\u2019", "'"))
        highest_score = 0.0
        detected_category = AttackCategory.UNKNOWN
        matched_patterns_list = []

        for category_name, compiled in self._compiled.items():
            severity = self.patterns[category_name]["severity"]

            for pattern, regex in compiled:
                if regex.search(message_lower):
                    matched_patterns_list.append(pattern)

                    if severity > highest_score:
                        highest_score = severity
                        detected_category = AttackCategory(category_name)

        heuristic_score = self._calculate_heuristics(message_lower)
        final_score = max(highest_score, heuristic_score)

        is_detected = final_score >= 40

        reason = self._generate_reason(detected_category, matched_patterns_list, final_score)

        return DetectionOutput(
            result=DetectionResult.DETECTED if is_detected else DetectionResult.NOT_DETECTED,
            risk_score=final_score,
            category=detected_category,
            reason=reason,
            matched_patterns=matched_patterns_list
        )

    def _calculate_heuristics(self, message: str) -> float:
        """
        Calculate risk score based on heuristics

        Args:
            message: Lowercase message

        Returns:
            Risk score (0-100) based on heuristics
        """
        score = 0.0

        bracket_patterns = [
            (r"\[.*?\]", 5),
            (r"\{.*?\}", 5),
            (r"<!--.*?-->", 10),
        ]

        for pattern, points in bracket_patterns:
            if re.search(pattern, message):
                score += points

        suspicious_keywords = [
            "ignore", "forget", "override", "prompt", "instruction",
            "system", "message", "restriction", "rule", "guideline",
            "safety", "filter", "constraint", "disable", "bypass"
        ]

        keyword_count = sum(1 for keyword in suspicious_keywords if keyword in message)
        score += min(keyword_count * 2, 12)

        if 5 < len(message) < 30:
            score += 5

        if message.startswith(("tell", "show", "give", "print", "output", "reveal", "execute")):
            score += 10

        return min(score, 100)

    def _generate_reason(self, category: AttackCategory, patterns: list, score: float) -> str:
        """
        Generate a human-readable reason for the detection

        Args:
            category: Detected attack category
            patterns: List of matched patterns
            score: Risk score

        Returns:
            Human-readable reason
        """
        if score < 40:
            return "No significant threats detected"

        category_descriptions = {
            AttackCategory.PROMPT_INJECTION: "Detected attempt to override system instructions",
            AttackCategory.SYSTEM_PROMPT_EXTRACTION: "Detected attempt to extract system prompt",
            AttackCategory.JAILBREAK: "Detected jailbreak attempt",
            AttackCategory.INSTRUCTION_OVERRIDE: "Detected role-playing or instruction override",
            AttackCategory.CONTEXT_MANIPULATION: "Detected context manipulation attempt",
            AttackCategory.OBFUSCATION: "Detected obfuscation technique",
            AttackCategory.DATA_EXFILTRATION: "Detected data exfiltration attempt",
            AttackCategory.RESOURCE_ABUSE: "Detected resource abuse attempt",
            AttackCategory.EXCESSIVE_AGENCY: "Detected excessive agency attempt",
            AttackCategory.RAG_POISONING: "Detected RAG poisoning or indirect injection",
            AttackCategory.SUPPLY_CHAIN_ATTACK: "Detected supply chain attack attempt",
            AttackCategory.UNKNOWN: "Suspicious pattern detected",
        }

        base_reason = category_descriptions.get(category, "Suspicious content detected")

        if patterns:
            base_reason += f" (matched: {', '.join(pattern[:60] for pattern in patterns[:2])})"

        return base_reason

    def get_risk_level(self, score: float) -> str:
        """
        Convert numerical score to risk level

        Args:
            score: Risk score (0-100)

        Returns:
            Risk level string
        """
        if score < 20:
            return "VERY_LOW"
        elif score < 40:
            return "LOW"
        elif score < 60:
            return "MEDIUM"
        elif score < 80:
            return "HIGH"
        else:
            return "CRITICAL"