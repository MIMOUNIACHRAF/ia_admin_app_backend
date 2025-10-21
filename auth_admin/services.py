from typing import List, Dict
from .models import QuestionReponse, AgentIA
from rapidfuzz import fuzz
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np
import re
import unicodedata

# ========== [1] NETTOYAGE TEXTE ==========
def normalize_text(text: str) -> str:
    if not text:
        return ""
    text = text.lower().strip()
    text = unicodedata.normalize("NFKD", text)
    text = "".join(c for c in text if not unicodedata.combining(c))
    text = re.sub(r"[^\w\s]", "", text)
    text = re.sub(r"\s+", " ", text)
    return text


# ========== [2] MÉTRIQUES ==========
def tfidf_similarity(q1: str, q2: str) -> float:
    vectorizer = TfidfVectorizer().fit([q1, q2])
    vectors = vectorizer.transform([q1, q2])
    return float(cosine_similarity(vectors[0], vectors[1])[0][0])


def fuzzy_similarity(q1: str, q2: str) -> float:
    return fuzz.token_set_ratio(q1, q2) / 100.0


# ========== [3] ESSAI EMBEDDINGS (si installés) ==========
try:
    from sentence_transformers import SentenceTransformer, util
    model = SentenceTransformer("all-MiniLM-L6-v2")
    USE_EMBEDDINGS = True
except Exception as e:
    print("⚠️ Embeddings non disponibles, fallback TFIDF/Fuzzy :", str(e))
    model = None
    USE_EMBEDDINGS = False


def semantic_similarity(q1: str, q2: str) -> float:
    """Mesure de similarité sémantique via embeddings."""
    if not USE_EMBEDDINGS:
        return 0.0
    emb1 = model.encode(q1, convert_to_tensor=True)
    emb2 = model.encode(q2, convert_to_tensor=True)
    return float(util.cos_sim(emb1, emb2))


# ========== [4] MÉLANGE HYBRIDE ==========
def hybrid_similarity(q1: str, q2: str) -> float:
    q1, q2 = normalize_text(q1), normalize_text(q2)
    s_tfidf = tfidf_similarity(q1, q2)
    s_fuzzy = fuzzy_similarity(q1, q2)
    s_sem = semantic_similarity(q1, q2)

    if USE_EMBEDDINGS:
        score = 0.2 * s_tfidf + 0.2 * s_fuzzy + 0.6 * s_sem
    else:
        score = 0.4 * s_tfidf + 0.6 * s_fuzzy
    return round(score, 3)


# ========== [5] MOTEUR PRINCIPAL ==========
def find_best_local_match(agent: AgentIA, user_question: str, threshold: float = 0.55, top_n: int = 5) -> List[Dict]:
    """
    Retourne une liste triée de correspondances :
    [
        {"question": "...", "reponse": "...", "score": 0.83, "source": "agent"},
        ...
    ]
    """
    question = normalize_text(user_question)
    if not question:
        return []

    all_matches = []

    # Questions propres à l’agent
    for qa in agent.questions_reponses.all():
        score = hybrid_similarity(question, qa.question)
        if score >= threshold:
            all_matches.append({
                "question": qa.question,
                "reponse": qa.reponse,
                "score": round(score, 3),
                "source": "agent"
            })

    # Questions dans les templates liés
    for template in agent.templates.prefetch_related("questions_reponses").all():
        for qa in template.questions_reponses.all():
            score = hybrid_similarity(question, qa.question)
            if score >= threshold:
                all_matches.append({
                    "question": qa.question,
                    "reponse": qa.reponse,
                    "score": round(score, 3),
                    "source": f"template: {template.nom}"
                })

    all_matches.sort(key=lambda x: x["score"], reverse=True)
    return all_matches[:top_n]
