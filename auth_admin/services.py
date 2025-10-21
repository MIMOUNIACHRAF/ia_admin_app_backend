from typing import Optional, List, Dict, Tuple
from .models import QuestionReponse, AgentIA
from rapidfuzz import fuzz
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np
import re
import unicodedata

# ========== UTILITAIRES ==========

def normalize_text(text: str) -> str:
    if not text:
        return ""
    text = text.lower().strip()
    text = unicodedata.normalize("NFKD", text)
    text = "".join(c for c in text if not unicodedata.combining(c))
    text = re.sub(r"[^\w\s]", "", text)
    text = re.sub(r"\s+", " ", text)
    return text


def tfidf_similarity(q1: str, q2: str) -> float:
    vectorizer = TfidfVectorizer().fit([q1, q2])
    vectors = vectorizer.transform([q1, q2])
    return float(cosine_similarity(vectors[0], vectors[1])[0][0])


def fuzzy_similarity(q1: str, q2: str) -> float:
    return fuzz.token_set_ratio(q1, q2) / 100.0


def hybrid_similarity(q1: str, q2: str) -> float:
    q1, q2 = normalize_text(q1), normalize_text(q2)
    s1 = tfidf_similarity(q1, q2)
    s2 = fuzzy_similarity(q1, q2)
    return round(0.4 * s1 + 0.6 * s2, 3)


# ========== NOUVELLE FONCTION PRINCIPALE ==========

def find_best_local_match(agent: AgentIA, user_question: str, threshold: float = 0.55, top_n: int = 5) -> List[Dict]:
    """
    Retourne une liste triée des meilleures correspondances locales :
    [
        {"question": "...", "reponse": "...", "score": 0.83, "source": "agent"},
        {"question": "...", "reponse": "...", "score": 0.72, "source": "template"},
        ...
    ]
    """
    question = normalize_text(user_question)
    if not question:
        return []

    all_matches = []

    # 1️⃣ Parcourir questions directes de l’agent
    for qa in agent.questions_reponses.all():
        score = hybrid_similarity(question, qa.question)
        if score >= threshold:
            all_matches.append({
                "question": qa.question,
                "reponse": qa.reponse,
                "score": round(score, 3),
                "source": "agent"
            })

    # 2️⃣ Parcourir les templates liés
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

    # 3️⃣ Trier du plus pertinent au moins pertinent
    all_matches.sort(key=lambda x: x["score"], reverse=True)

    # 4️⃣ Retourner top N
    return all_matches[:top_n]
