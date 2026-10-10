from __future__ import annotations

import random
from dataclasses import dataclass

from .crypto_engine import TrapdoorGenerator


@dataclass(frozen=True, slots=True)
class Defense:
    name: str
    epochs: int = 1
    pad: bool = False


DEFENSES = (
    Defense("none"),
    Defense("padding", pad=True),
    Defense("epochs=4", epochs=4),
    Defense("epochs=8", epochs=8),
    Defense("padding+epochs=4", epochs=4, pad=True),
    Defense("padding+epochs=8", epochs=8, pad=True),
)


def synthetic_corpus(docs: int, vocab: int, words_per_doc: int, seed: int, zipf: float = 1.1) -> list[set[int]]:
    rng = random.Random(seed)
    weights = [1 / (rank + 1) ** zipf for rank in range(vocab)]
    return [set(rng.choices(range(vocab), weights, k=words_per_doc)) for _ in range(docs)]


def server_view(corpus: list[set[int]], defense: Defense, key: bytes, seed: int) -> tuple[dict[str, set[int]], dict[str, int], dict[str, int]]:
    rng = random.Random(seed)
    generator = TrapdoorGenerator(key, "attack-lab")
    postings: dict[str, set[int]] = {}
    truth: dict[str, int] = {}
    epochs: dict[str, int] = {}
    per_epoch = -(-len(corpus) // defense.epochs)
    for doc_id, words in enumerate(corpus):
        epoch = doc_id // per_epoch
        for word in words:
            token = generator.create(f"w{word}", epoch)
            postings.setdefault(token, set()).add(doc_id)
            truth[token] = word
            epochs[token] = epoch
    if defense.pad:
        for ids in postings.values():
            target = min(1 << (len(ids) - 1).bit_length(), len(corpus))
            while len(ids) < target:
                ids.add(rng.randrange(len(corpus)))
    return postings, truth, epochs


def count_attack(
    postings: dict[str, set[int]], truth: dict[str, int], epochs: dict[str, int], aux_rank: list[int], top_k: int, seed: int
) -> float:
    rng = random.Random(seed)
    groups: dict[int, list[str]] = {}
    for token in postings:
        groups.setdefault(epochs[token], []).append(token)
    hits = total = 0
    for tokens in groups.values():
        rng.shuffle(tokens)
        tokens.sort(key=lambda t: -len(postings[t]))
        for position, token in enumerate(tokens):
            if truth[token] < top_k:
                total += 1
                hits += aux_rank[min(position, len(aux_rank) - 1)] == truth[token]
    return hits / max(1, total)


def run_attack(
    docs: int = 2000,
    vocab: int = 400,
    words_per_doc: int = 14,
    top_k: int = 40,
    trials: int = 5,
    seed: int = 7,
    defenses: tuple[Defense, ...] = DEFENSES,
) -> list[dict[str, float | str]]:
    results = []
    for defense in defenses:
        recovered, overhead, tokens = [], [], []
        for trial in range(trials):
            corpus = synthetic_corpus(docs, vocab, words_per_doc, seed + trial)
            aux = synthetic_corpus(docs, vocab, words_per_doc, seed + 1000 + trial)
            df = [0] * vocab
            for words in aux:
                for word in words:
                    df[word] += 1
            aux_rank = sorted(range(vocab), key=lambda w: -df[w])
            key = random.Random(seed + trial).randbytes(32)
            postings, truth, epochs = server_view(corpus, defense, key, seed + trial)
            real = sum(len(words) for words in corpus)
            recovered.append(count_attack(postings, truth, epochs, aux_rank, top_k, seed + trial))
            overhead.append(sum(len(ids) for ids in postings.values()) / real)
            tokens.append(len(postings))
        results.append(
            {
                "defense": defense.name,
                "top_k_recovery_pct": round(100 * sum(recovered) / trials, 1),
                "index_size_x": round(sum(overhead) / trials, 2),
                "tokens_seen": round(sum(tokens) / trials),
                "lookups_per_query": defense.epochs,
            }
        )
    return results


if __name__ == "__main__":
    for row in run_attack():
        print(row)