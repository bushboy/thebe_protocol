"""Intent signature generation and verification.

This module implements semantic intent verification using sentence transformers
to detect prompt injection and intent drift.

Requirements: 6.1, 6.2, 6.3
"""

import hashlib
import numpy as np
from datetime import datetime
from typing import List
from sentence_transformers import SentenceTransformer
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

from shared.schemas import IntentSignature
from .config import config


class IntentSigner:
    """Handles intent signature generation and verification."""

    def __init__(self, model_name: str = None, similarity_threshold: float = None):
        """Initialize the intent signer.

        Args:
            model_name: Name of the sentence-transformer model
            similarity_threshold: Minimum similarity score for alignment
        """
        self.model_name = model_name or config.model_name
        self.similarity_threshold = similarity_threshold or config.similarity_threshold
        self.model = None
        self._private_key = None

    def load_model(self):
        """Load the sentence-transformer model."""
        if self.model is None:
            self.model = SentenceTransformer(self.model_name)

    def _load_private_key(self):
        """Load the private key for signing."""
        if self._private_key is None:
            with open(config.signing_key_path, 'rb') as f:
                self._private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend()
                )
        return self._private_key

    def _generate_embedding(self, text: str) -> List[float]:
        """Generate semantic embedding from text.

        Args:
            text: Input text to embed

        Returns:
            List of floats representing the embedding vector

        Requirements: 6.1, 6.2
        """
        if self.model is None:
            self.load_model()

        embedding = self.model.encode(text, convert_to_numpy=True)
        return embedding.tolist()

    def _compute_hash(self, text: str) -> str:
        """Compute SHA256 hash of text.

        Args:
            text: Input text to hash

        Returns:
            Hexadecimal hash string
        """
        return hashlib.sha256(text.encode('utf-8')).hexdigest()

    def _sign_data(self, data: str) -> str:
        """Sign data with private key.

        Args:
            data: Data to sign

        Returns:
            Base64-encoded signature
        """
        private_key = self._load_private_key()
        signature = private_key.sign(
            data.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        import base64
        return base64.b64encode(signature).decode('utf-8')

    def sign_intent(self, user_goal: str, allowed_actions: List[str]) -> IntentSignature:
        """Generate an intent signature for a user goal.

        Args:
            user_goal: The user's stated goal
            allowed_actions: List of permitted action types

        Returns:
            IntentSignature object with embedding, hash, and signature

        Requirements: 6.1, 6.2
        """
        # Generate embedding
        embedding = self._generate_embedding(user_goal)

        # Compute hash
        goal_hash = self._compute_hash(user_goal)

        # Compute a representative semantic score for this intent signature.
        # We use the best similarity across allowed actions as a compact summary
        # that can be surfaced downstream in policy decisions and audit traces.
        allowed_action_scores = []
        for allowed_action in allowed_actions:
            action_embedding = self._generate_embedding(allowed_action)
            allowed_action_scores.append(
                self._compute_cosine_similarity(embedding, action_embedding)
            )

        semantic_similarity_score = max(allowed_action_scores) if allowed_action_scores else 0.0

        # Create signature data
        timestamp = datetime.utcnow()
        signature_data = (
            f"{goal_hash}:{','.join(allowed_actions)}:"
            f"{semantic_similarity_score:.6f}:{self.similarity_threshold:.6f}:"
            f"{timestamp.isoformat()}"
        )
        signature = self._sign_data(signature_data)

        return IntentSignature(
            embedding=embedding,
            hash=goal_hash,
            allowed_actions=allowed_actions,
            semantic_similarity_score=semantic_similarity_score,
            semantic_match_threshold=self.similarity_threshold,
            timestamp=timestamp,
            signature=signature
        )

    def verify_intent(self, intent_signature: IntentSignature, proposed_action: str) -> dict:
        """Verify if a proposed action aligns with the original intent.

        Args:
            intent_signature: The original intent signature
            proposed_action: The action being proposed

        Returns:
            Dictionary with alignment decision and similarity score

        Requirements: 6.3
        """
        # Generate embedding for proposed action
        action_embedding = self._generate_embedding(proposed_action)

        # Compute cosine similarity
        similarity_score = self._compute_cosine_similarity(
            intent_signature.embedding,
            action_embedding
        )

        # Check alignment
        aligned = similarity_score >= self.similarity_threshold

        return {
            "aligned": aligned,
            "similarity_score": float(similarity_score),
            "threshold": self.similarity_threshold
        }

    def _compute_cosine_similarity(self, embedding1: List[float], embedding2: List[float]) -> float:
        """Compute cosine similarity between two embeddings.

        Args:
            embedding1: First embedding vector
            embedding2: Second embedding vector

        Returns:
            Cosine similarity score in range [0, 1]

        Requirements: 6.3
        """
        vec1 = np.array(embedding1)
        vec2 = np.array(embedding2)

        # Compute cosine similarity
        dot_product = np.dot(vec1, vec2)
        norm1 = np.linalg.norm(vec1)
        norm2 = np.linalg.norm(vec2)

        if norm1 == 0 or norm2 == 0:
            return 0.0

        similarity = dot_product / (norm1 * norm2)

        # Normalize to [0, 1] range (cosine similarity is in [-1, 1])
        normalized_similarity = (similarity + 1) / 2

        return float(normalized_similarity)
