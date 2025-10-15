from typing import Optional, Tuple, List
from .models import QuestionReponse, AgentIA
from rapidfuzz import fuzz
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np
import re
import unicodedata

# ========== UTILITAIRES DE NETTOYAGE ==========

def normalize_text(text: str) -> str:
    """Nettoie et normalise le texte : minuscules, accents, ponctuation, espaces."""
    if not text:
        return ""
    text = text.lower().strip()
    text = unicodedata.normalize("NFKD", text)
    text = "".join(c for c in text if not unicodedata.combining(c))  # retire les accents
    text = re.sub(r"[^\w\s]", "", text)  # supprime ponctuation
    text = re.sub(r"\s+", " ", text)  # espaces multiples
    return text


# ========== SIMILARITÉS MULTI-NIVEAUX ==========

def tfidf_similarity(q1: str, q2: str) -> float:
    """Mesure la similarité via TF-IDF + cosine."""
    vectorizer = TfidfVectorizer().fit([q1, q2])
    vectors = vectorizer.transform([q1, q2])
    sim = cosine_similarity(vectors[0], vectors[1])[0][0]
    return float(sim)


def fuzzy_similarity(q1: str, q2: str) -> float:
    """Mesure la similarité floue (typos, ordre de mots, etc.)"""
    return fuzz.token_set_ratio(q1, q2) / 100.0


def hybrid_similarity(q1: str, q2: str) -> float:
    """
    Combine plusieurs approches :
      - 40% TF-IDF (sémantique légère)
      - 60% Fuzzy (typos, reformulations)
    """
    q1, q2 = normalize_text(q1), normalize_text(q2)
    s1 = tfidf_similarity(q1, q2)
    s2 = fuzzy_similarity(q1, q2)
    return round(0.4 * s1 + 0.6 * s2, 3)


# ========== MOTEUR PRINCIPAL DE MATCHING ==========

def find_best_local_match(agent: AgentIA, user_question: str, threshold: float = 0.65) -> Optional[Tuple[QuestionReponse, float]]:
    """
    Recherche la meilleure correspondance locale avec approche hybride.
    - Analyse questions agent en priorité
    - Si aucun match suffisant, cherche dans les templates liés
    Retourne (QuestionReponse, score) si score >= threshold
    """
    question = normalize_text(user_question)
    if not question:
        return None

    best_qr = None
    best_score = 0.0

    # 1️⃣ Recherche dans les questions de l’agent
    for qa in agent.questions_reponses.all():
        score = hybrid_similarity(question, qa.question)
        if score > best_score:
            best_qr = qa
            best_score = score

    # 2️⃣ Recherche dans les templates si score encore faible
    if best_score < threshold:
        for template in agent.templates.prefetch_related("questions_reponses").all():
            for qa in template.questions_reponses.all():
                score = hybrid_similarity(question, qa.question)
                if score > best_score:
                    best_qr = qa
                    best_score = score

    # 3️⃣ Retour final
    if best_score >= threshold:
        return best_qr, best_score

    return None
