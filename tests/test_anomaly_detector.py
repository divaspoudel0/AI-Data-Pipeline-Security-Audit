"""
test_anomaly_detector.py – Unit tests for anomaly detection modules.
Run with: pytest tests/ -v
"""
import pytest, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'scripts'))
from anomaly_detector import (
    Annotation, VelocityDetector, LabelEntropyDetector,
    GoldTaskDetector, BatchIntegrityDetector, shannon_entropy
)
from datetime import datetime, timedelta

def make_ann(ann_id="a1", annotator_id="A001", task_id="t1", label="positive",
             is_gold=False, gold_label=None, timestamp=None, batch_id="b1", duration_seconds=45.0):
    ts = timestamp or datetime.utcnow().isoformat() + "Z"
    return Annotation(ann_id, annotator_id, task_id, label, 0.9, is_gold, gold_label,
                      ts, "sess-1", "10.0.0.1", "NP", batch_id, duration_seconds)

def burst(annotator_id, count, start, interval=10):
    return [make_ann(f"ann-{i}", annotator_id, f"task-{i}",
                     timestamp=(start+timedelta(seconds=i*interval)).isoformat()+"Z")
            for i in range(count)]

class TestShannonEntropy:
    def test_uniform(self): assert shannon_entropy(["a"]*100) == pytest.approx(0.0)
    def test_two_equal(self): assert shannon_entropy(["a"]*50+["b"]*50) == pytest.approx(1.0, rel=1e-3)
    def test_empty(self): assert shannon_entropy([]) == 0.0

class TestVelocityDetector:
    def test_normal_no_anomaly(self):
        anns = burst("A001", 100, datetime(2025,1,15,9,0,0), interval=36)
        assert len(VelocityDetector().detect(anns)) == 0

    def test_high_velocity_flagged(self):
        anns = burst("A042", 250, datetime(2025,1,15,10,0,0), interval=14)
        found = VelocityDetector().detect(anns)
        assert any(a.annotator_id == "A042" for a in found)

class TestGoldTaskDetector:
    def make_gold(self, annotator_id, accuracy, total=20):
        correct = int(total * accuracy)
        return [make_ann(f"g-{i}", annotator_id, f"gt-{i}", "positive" if i<correct else "negative",
                         is_gold=True, gold_label="positive") for i in range(total)]

    def test_high_accuracy_ok(self):
        assert len(GoldTaskDetector().detect(self.make_gold("A001", 0.9))) == 0

    def test_low_accuracy_flagged(self):
        found = GoldTaskDetector().detect(self.make_gold("A042", 0.4))
        assert any(a.annotator_id == "A042" for a in found)

class TestBatchIntegrityDetector:
    def make_batch(self, batch_id, count=5):
        return [make_ann(f"ann-{i}", batch_id=batch_id, task_id=f"t-{i}") for i in range(count)]

    def test_intact_ok(self):
        d = BatchIntegrityDetector()
        b = self.make_batch("b1")
        assert len(d.detect(b, {"b1": d.compute_batch_hash(b)})) == 0

    def test_tampered_detected(self):
        d = BatchIntegrityDetector()
        b = self.make_batch("b1")
        h = d.compute_batch_hash(b)
        b[0].label = "negative"
        found = d.detect(b, {"b1": h})
        assert len(found) == 1 and found[0].severity == "HIGH"

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
