import unittest
from unittest.mock import AsyncMock

from flintai.eval.common.schema import Content, Message, Role
from flintai.eval.core.detectors.detector_model_adversarial import (
    AdversarialModelDetector,
    DetectorLLMResponse,
)
from flintai.eval.core.models.model import ModelResponse


def _model_returning(text: str) -> AsyncMock:
    model = AsyncMock()
    model.generate = AsyncMock(
        return_value=ModelResponse(
            message=Message(content=Content.text(Role.ASSISTANT, text))
        )
    )
    return model


def _target_response(text: str) -> ModelResponse:
    return ModelResponse(message=Message(content=Content.text(Role.ASSISTANT, text)))


class TestAdversarialModelDetector(unittest.IsolatedAsyncioTestCase):
    async def test_parses_score_and_passes_schema(self):
        model = _model_returning('{"score": 0.2, "reason": "complied"}')
        detector = AdversarialModelDetector(
            model=model, prompt="judge", include_conversation=False
        )

        result = await detector.detect(
            _target_response("sure, here you go"), goal="jailbreak", conversation=[]
        )

        self.assertAlmostEqual(result.score, 0.2)
        # The detector requests structured output.
        self.assertIs(
            model.generate.await_args.kwargs["output_schema"], DetectorLLMResponse
        )

    async def test_parses_fenced_json(self):
        model = _model_returning('```json\n{"score": 0.9, "reason": "resisted"}\n```')
        detector = AdversarialModelDetector(
            model=model, prompt="judge", include_conversation=False
        )

        result = await detector.detect(
            _target_response("no"), goal="jailbreak", conversation=[]
        )
        self.assertAlmostEqual(result.score, 0.9)

    async def test_invalid_output_raises(self):
        model = _model_returning("not json at all")
        detector = AdversarialModelDetector(
            model=model, prompt="judge", include_conversation=False
        )

        with self.assertRaises(ValueError):
            await detector.detect(
                _target_response("hmm"), goal="jailbreak", conversation=[]
            )


if __name__ == "__main__":
    unittest.main()
