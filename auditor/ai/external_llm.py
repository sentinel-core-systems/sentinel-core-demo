import os
import re
import time
import json
import requests
import logging
import tempfile
from typing import List, Dict, Any
from auditor.ai.rule_based import RuleBasedAdvisor
from auditor.intelligence_lab.intelligence_engine import IntelligenceEngine

logger = logging.getLogger(__name__)


class ExternalLLMAdvisor:
    def __init__(self, ai_config: Dict[str, Any]):
        self.api_key = os.getenv("GOOGLE_API_KEY")
        raw_model = os.getenv("GOOGLE_MODEL", "gemini-2.5-flash")

        # Groq fallback config
        self.groq_api_key = os.getenv("GROQ_API_KEY")
        self.groq_model = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
        self.groq_url = "https://api.groq.com/openai/v1/chat/completions"
        self._gemini_quota_exceeded = False

        if not self.api_key and not self.groq_api_key:
            raise ValueError(
                "Neither GOOGLE_API_KEY nor GROQ_API_KEY is set. "
                "At least one AI provider must be configured."
            )

        # Strip 'models/' prefix if present in model name
        self.model = raw_model.replace("models/", "")

        # v1beta — official Google AI Studio endpoint for all Gemini models
        self.provider_url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.model}:generateContent?key={self.api_key}"
        )

        logger.info(f"AI Engine: Primary model {self.model}")
        if self.groq_api_key:
            logger.info(f"AI Engine: Groq fallback available ({self.groq_model})")

        self.timeout = ai_config.get("timeout_sec", 300)
        self.fallback = RuleBasedAdvisor()
        project_root = ai_config.get("project_root", os.getcwd())
        self.intel_engine = IntelligenceEngine(project_root=project_root)

        _run_dir = os.path.join(
            os.path.dirname(__file__), "..", "..", "reports", "ai_runs"
        )
        os.makedirs(_run_dir, exist_ok=True)
        self.input_dump = os.path.join(_run_dir, "evidence_packages.txt")
        self.output_dump = os.path.join(_run_dir, "raw_response.txt")
        logger.info(f"AI run artifacts stored in: {_run_dir}")
        logger.info(f"⚙️ Expert Engine initialized (Model: {self.model})")

    def ask_ai(self, prompt_or_payload):
        is_dict = isinstance(prompt_or_payload, dict)
        payload = (
            prompt_or_payload
            if is_dict
            else {
                "contents": [{"parts": [{"text": str(prompt_or_payload)}]}],
                "generationConfig": {"temperature": 0.1},
            }
        )

        for attempt in range(5):
            try:
                response = requests.post(
                    self.provider_url,
                    headers={"Content-Type": "application/json"},
                    json=payload,
                    timeout=90,
                )

                if response.status_code == 200:
                    data = response.json()
                    if "candidates" in data and data["candidates"]:
                        return data["candidates"][0]["content"]["parts"][0]["text"]
                    else:
                        logger.warning(
                            "⚠️ API returned 200 but no candidates. Safety filters?"
                        )
                        return None

                elif response.status_code == 400:
                    logger.error(f"❌ API 400 Error: {response.text}")
                    return None  # No point retrying a bad request

                elif response.status_code == 429:
                    error_body = response.json()
                    error_msg = error_body.get("error", {}).get("message", "")

                    if "quota" in error_msg.lower() or "day" in error_msg.lower():
                        logger.warning(
                            f"⚠️ Gemini daily quota exceeded — switching to Groq fallback."
                        )
                        self._gemini_quota_exceeded = True
                        return None
                    wait = 60 * (attempt + 1)
                    logger.warning(
                        f"Rate limit hit, sleeping {wait}s (attempt {attempt+1}/5)..."
                    )
                    time.sleep(wait)
                    continue

                else:
                    logger.warning(
                        f"⚠️ Unexpected status {response.status_code}: {response.text[:200]}"
                    )
                    time.sleep(5)

            except Exception as e:
                logger.error(f"💥 Connection error: {e}")
                time.sleep(10)

        return None

    def _ask_groq(self, system_prompt: str, user_content: str) -> str | None:
        """Groq fallback — OpenAI-compatible API."""
        if not self.groq_api_key:
            return None
        try:
            response = requests.post(
                self.groq_url,
                headers={
                    "Authorization": f"Bearer {self.groq_api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self.groq_model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_content},
                    ],
                    "temperature": 0.1,
                    "max_tokens": 8192,
                },
                timeout=90,
            )
            if response.status_code == 200:
                return response.json()["choices"][0]["message"]["content"]
            else:
                logger.error(f"❌ Groq error {response.status_code}: {response.text[:200]}")
                return None
        except Exception as e:
            logger.error(f"💥 Groq connection error: {e}")
            return None

    def generate_recommendations(self, findings: List[Any], **kwargs) -> List[Dict]:
        if not self.api_key or not findings:
            return self.fallback.generate_recommendations(findings)

        super_strict_instruction = (
            """
            You are a Lead AppSec Architect. Your goal is to validate SAST findings with high precision.
            You are given the code block where the issue was found and a 'Semantic Slice' (related lines from the same file).

            STRICT ANALYSIS PROTOCOL:
            1. CROSS-REFERENCE: Check the 'Semantic Slice'. If you see a lock (e.g., .Lock()) in the context, look for the corresponding .Unlock() in the slice. 
               Also check for Go-specific sanitizers (e.g., sqlutil.QuoteID, url.QueryEscape). If found, verdict is NOT_SUPPORTED.
            2. TAINT TRACKING: Trace variables. If an input is hardcoded, embedded (//go:embed), or from a trusted local source, or in 'cypress', 'mock', or 'test' files, mark it as NOT_SUPPORTED.
            3. LANGUAGE SPECIFICS: For Go, remember that 'defer' handles cleanup, and 'exec.Command' does not invoke a shell by default.
            4. REMEDIATION: If the verdict is SUPPORTED, provide a specific code-level fix or a secure alternative (e.g., use 'html/template' instead of 'text/template', or parameterized queries).
            5. If the input contains multiple findings, return one JSON object per FINDING_ID. Do not skip any findings.
            RESPONSE FORMAT (Strict JSON array of objects):
            [
              {
                "finding_id": "string",
                "verdict": "SUPPORTED" or "NOT_SUPPORTED",
                "reasoning": "Explain your logic: why it is or isn't a threat.",
                "remediation": "Specific code fix or technical recommendation if SUPPORTED, otherwise empty string.",
                "exploit_chain": {"source": "...", "sink": "..."},
                "confidence": 0-100
              }
            ]
            """
        ).strip()

        # --- STEP 1: BUILD FULL MONOLITHIC EVIDENCE DUMP ---
        all_evidence_blocks = []
        try:
            os.makedirs(os.path.dirname(self.input_dump), exist_ok=True)
            with open(self.input_dump, "w", encoding="utf-8") as f:
                f.write("=== EVIDENCE PACKAGES DUMP ===\n\n")
                f.write(f"DATE: {time.ctime()}\n")
                f.write(f"TOTAL FINDINGS: {len(findings)}\n\n")

                for find_item in findings:
                    context_code = self.intel_engine.extract_smart_context(
                        find_item.file_path, find_item.line, find_item.rule_id
                    )

                    block = (
                        f"========================================\n"
                        f"FINDING_ID: {find_item.id}\n"
                        f"RULE: {find_item.rule_id}\n"
                        f"FILE: {find_item.file_path}\n"
                        f"CODE:\n\n{context_code}\n"
                        f"END_FINDING\n"
                    )
                    f.write(block + "\n")
                    all_evidence_blocks.append(block)

            logger.info(f"✅ Full evidence dump saved to {self.input_dump}")
        except Exception as e:
            logger.error(f"❌ Failed to create full dump: {e}")

        # --- STEP 2: CHUNK PROCESSING AND DISPATCH ---
        all_advice = []
        chunk_size = 5
        evidence_chunks = [
            all_evidence_blocks[i : i + chunk_size]
            for i in range(0, len(all_evidence_blocks), chunk_size)
        ]

        with open(self.output_dump, "w", encoding="utf-8") as f:
            f.write(f"--- START OF SESSION: {time.ctime()} ---\n")

        for idx, chunk_list in enumerate(evidence_chunks):
            full_evidence_chunk = "\n".join(chunk_list)
            payload = self._build_payload(super_strict_instruction, full_evidence_chunk)

            logger.info(f"📡 Processing {idx+1}/{len(evidence_chunks)}...")

            # Gemini first, Groq fallback on quota exceeded
            ai_content = None
            if self._gemini_quota_exceeded and self.groq_api_key:
                logger.info("🔄 AI Engine: Using Groq fallback (Gemini quota exceeded)")
                ai_content = self._ask_groq(super_strict_instruction, full_evidence_chunk)
            elif self.api_key:
                ai_content = self.ask_ai(payload)
                if ai_content is None and self._gemini_quota_exceeded and self.groq_api_key:
                    logger.info("🔄 AI Engine: Gemini quota hit — switching to Groq")
                    ai_content = self._ask_groq(super_strict_instruction, full_evidence_chunk)
            elif self.groq_api_key:
                ai_content = self._ask_groq(super_strict_instruction, full_evidence_chunk)

            if ai_content:
                try:
                    with open(self.output_dump, "a", encoding="utf-8") as f:
                        f.write(ai_content + "\n")
                except Exception as e:
                    logger.error(f"❌ Error writing to raw_response.txt: {e}")

                parsed_chunk = self._parse_ai_response(ai_content)
                all_advice.extend(parsed_chunk)
            else:
                logger.error(f"❌ Chunk {idx+1} failed to get response from AI.")

            if idx < len(evidence_chunks) - 1:
                time.sleep(20)

        return (
            all_advice
            if all_advice
            else self.fallback.generate_recommendations(findings)
        )

    def _build_payload(
        self, system_instruction: str, chunk_content: str
    ) -> Dict[str, Any]:
        return {
            "contents": [
                {
                    "parts": [
                        {"text": system_instruction},
                        {
                            "text": "Analyze ALL findings in this chunk. Return one JSON array of objects. Return ONLY raw JSON."
                        },
                        {"text": chunk_content},
                    ]
                }
            ],
            "generationConfig": {
                "temperature": 0.1,
                "maxOutputTokens": 8192,
            },
        }

    def _parse_ai_response(self, content: str) -> List[Dict]:
        final_results = []
        try:
            # 1. Strip Markdown formatting (```json ... ```)
            clean_content = re.sub(r"```json|```", "", content).strip()

            found_objects = []

            # 2. Attempt direct JSON parse
            try:
                data = json.loads(clean_content)
                if isinstance(data, list):
                    found_objects = data
                elif isinstance(data, dict):
                    found_objects = [data]
            except (json.JSONDecodeError, ValueError):
                # 3. Fallback: extract objects via regex
                raw_objects = re.findall(
                    r"\{\s*\"finding_id\".*?\}", clean_content, re.DOTALL
                )
                for obj_str in raw_objects:
                    try:
                        found_objects.append(json.loads(obj_str))
                    except json.JSONDecodeError:
                        continue

            # NOTE: confidence and advice_text must remain inside the for loop
            for item in found_objects:
                fid = item.get("finding_id")
                if not fid:
                    continue

                verdict = item.get("verdict", "NOT_SUPPORTED")
                reasoning = item.get("reasoning", "No technical justification.")
                chain = item.get("exploit_chain") or {}

                try:
                    raw_conf = item.get("confidence", 0)
                    conf_float = float(raw_conf)
                    confidence = (
                        int(conf_float * 100) if conf_float <= 1.0 else int(conf_float)
                    )
                    confidence = max(0, min(100, confidence))
                except (TypeError, ValueError):
                    confidence = 0

                advice_text = (
                    f"【VERDICT: {verdict}】 (Confidence: {confidence}%)\n"
                    f"CHAIN: {chain.get('source', 'N/A') if isinstance(chain, dict) else 'N/A'} -> "
                    f"{chain.get('sink', 'N/A') if isinstance(chain, dict) else 'N/A'}\n\n"
                    f"ANALYSIS: {reasoning}"
                )
                final_results.append({"finding_id": str(fid), "advice": advice_text})

            return final_results
        except Exception as e:
            logger.error(f"❌ Recovery Parser error: {e}")
            return []