import sys

print("🔧 Python executable:", sys.executable)
print("📦 Python path:", sys.path)

try:
    import sigma
    print("✅ Module 'sigma' importé depuis :", sigma.__file__)
except Exception as e:
    print("❌ Erreur import sigma:", e)
    sys.exit(1)

try:
    from sigma.collection import SigmaCollection
    print("✅ SigmaCollection OK")
except Exception as e:
    print("❌ Erreur import SigmaCollection:", e)

# Test pipeline Microsoft (inclus dans pysigma-backend-kusto)
try:
    from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline
    print("✅ Pipeline Microsoft XDR OK")
except Exception as e:
    print("❌ Erreur import microsoft_xdr_pipeline:", e)

try:
    from sigma.pipelines.sentinelasim import sentinel_asim_pipeline
    print("✅ Pipeline Sentinel Simulation OK")
except Exception as e:
    print("❌ Erreur import sentinelasim_pipeline:", e)

# Test backend Kusto
try:
    from sigma.backends.kusto import KustoBackend
    print("✅ Backend Kusto (Sentinel) OK")
except Exception as e:
    print("❌ Erreur import KustoBackend:", e)

print("🎉 Vérification terminée ! Si tout est vert, tu peux utiliser sigma-cli avec Sentinel.")
