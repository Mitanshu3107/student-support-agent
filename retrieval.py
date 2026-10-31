"""Policy retrieval: split the handbook into section chunks and rank them with BM25.

Pure Python, no external dependencies. Only the top-k relevant chunks are returned to the
agent, and a coverage check lets the retriever say "nothing relevant" instead of returning
the least-bad chunk for a question the handbook does not cover.
"""
import math
import re
from collections import Counter

STOPWORDS = set(
    "a an the and or of to in on for is are was were be been can could i my me we you your it its "
    "this that these those with as at by from if do does did what how when where will would should "
    "not no any there their they he she am so than then also about into up out "
    "condition conditions criteria criterion rule rules policy policies requirement requirements information info "
    "please tell give need want get".split()
)


def stem(word: str) -> str:
    """Very light suffix stripping so 'failed'/'fails' and 'instalments'/'instalment' match."""
    for suffix in ("ies", "ing", "ed", "es", "s"):
        if word.endswith(suffix) and len(word) - len(suffix) >= 3:
            return word[: -len(suffix)] + ("y" if suffix == "ies" else "")
    return word


def tokenize(text: str) -> list:
    words = re.findall(r"[a-z0-9]+", text.lower().replace("installment", "instalment"))
    return [stem(w) for w in words if w not in STOPWORDS and len(w) > 1]


class PolicyRetriever:
    K1 = 1.5
    B = 0.75
    MIN_COVERAGE = 0.4  # share of (idf-weighted) query terms the best chunk must contain

    def __init__(self, handbook_path: str):
        with open(handbook_path, encoding="utf-8") as f:
            self.raw = f.read()
        self.chunks = self._split(self.raw)
        self._tokens = [Counter(tokenize(c["title"] + " " + c["title"] + " " + c["text"])) for c in self.chunks]
        self._lengths = [sum(t.values()) for t in self._tokens]
        self._avg_len = sum(self._lengths) / len(self._lengths)
        self._df = Counter()
        for toks in self._tokens:
            self._df.update(toks.keys())
        self._vocab = list(self._df)

    @staticmethod
    def _split(raw: str) -> list:
        chunks = []
        for block in re.split(r"(?m)^## ", raw)[1:]:
            heading, _, body = block.partition("\n")
            m = re.match(r"(\d+)\.\s*(.*)", heading.strip())
            number, title = (m.group(1), m.group(2)) if m else (str(len(chunks) + 1), heading.strip())
            chunks.append({"chunk_id": f"handbook#{number}", "title": title, "text": body.strip()})
        return chunks

    def _variants(self, term: str) -> list:
        """Vocabulary terms that count as this query term: itself, or a prefix relative ('exam' ~ 'examination')."""
        return [v for v in self._vocab
                if v == term or (min(len(v), len(term)) >= 3 and (v.startswith(term) or term.startswith(v)))]

    def _idf(self, term: str) -> float:
        n = len(self.chunks)
        variants = self._variants(term)
        df = min((self._df[v] for v in variants), default=0)
        return math.log(1 + (n - df + 0.5) / (df + 0.5))

    def _weight(self, term: str) -> float:
        """Terms that appear nowhere in the handbook count double: a question about something the
        handbook never mentions (e.g. 'hostel') should not be rescued by generic words like 'fee'."""
        return self._idf(term) * (1.0 if self._variants(term) else 2.0)

    def _bm25(self, q_terms, i: int) -> float:
        score = 0.0
        tf = self._tokens[i]
        for t in q_terms:
            f = sum(tf.get(v, 0) for v in self._variants(t))
            if f:
                score += self._idf(t) * f * (self.K1 + 1) / (f + self.K1 * (1 - self.B + self.B * self._lengths[i] / self._avg_len))
        return score

    def _coverage(self, q_terms, i: int) -> float:
        total = sum(self._weight(t) for t in q_terms)
        hit = sum(self._weight(t) for t in q_terms if any(v in self._tokens[i] for v in self._variants(t)))
        return hit / total if total else 0.0

    def search(self, query: str, k: int = 2) -> list:
        """Return up to k chunks, best first. Empty list means 'no sufficiently relevant policy'."""
        q_terms = sorted(set(tokenize(query)))
        if not q_terms:
            return []
        ranked = sorted(range(len(self.chunks)), key=lambda i: -self._bm25(q_terms, i))
        results = []
        for i in ranked[:k]:
            score, cov = self._bm25(q_terms, i), self._coverage(q_terms, i)
            if score > 0 and cov >= self.MIN_COVERAGE:
                results.append({**self.chunks[i], "score": round(score, 2), "coverage": round(cov, 2)})
        return results
