# -*- coding: utf-8 -*-
import sys
import os
import subprocess
import tempfile
import shutil
import logging
from typing import Tuple

log = logging.getLogger("shadowcoder.sandbox")

class SandboxRunner:
    @staticmethod
    def _is_docker_available() -> bool:
        return shutil.which("docker") is not None

    def run_exploit(self, source_code: str, payload: str, timeout: int = 15) -> Tuple[bool, str]:
        """
        Runs the provided source code in a sandbox with the given payload.
        Returns (success, output).
        """
        # Create a temporary file with the payload-injected wrapper
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode='w', encoding='utf-8') as f:
            # We use a wrapper to inject the payload into the environment
            # and then run the user's code.
            wrapper = f"""# -*- coding: utf-8 -*-
import sys
import os

# Retrieve payload safely from environment to avoid encoding syntax errors
_payload = os.environ.get('SC_PAYLOAD', '')

try:
    # User code below:
{chr(10).join('    ' + line for line in source_code.splitlines())}
except Exception as e:
    print(f"User code initialization error: {{e}}")

# Auto-execute functions to trigger the sink
for name, obj in list(locals().items()):
    if callable(obj) and not name.startswith('_'):
        try:
            obj()
        except TypeError:
            try:
                obj(_payload)
            except Exception:
                pass
        except Exception:
            pass
"""
            f.write(wrapper)
            temp_path = f.name

        try:
            env = os.environ.copy()
            env['SC_PAYLOAD'] = payload

            # True Docker Sandboxing
            if SandboxRunner._is_docker_available():
                try:
                    # Use a throwaway alpine python container with resource limits and no network
                    # Mount the temp file directly to avoid stdin encoding issues on Windows
                    # Make sure the temp file path is converted to a string format Docker handles
                    result = subprocess.run(
                        [
                            "docker", "run", "--rm", 
                            "-v", f"{temp_path}:/sandbox.py:ro",
                            "-e", "SC_PAYLOAD",
                            "-e", "PYTHONIOENCODING=utf-8",
                            "-e", "LANG=C.UTF-8",
                            "--network", "none", 
                            "--memory", "128m", 
                            "--cpus", "0.5", 
                            "python:3.11-alpine", "python", "/sandbox.py"
                        ],
                        capture_output=True,
                        text=True,
                        encoding='utf-8',
                        timeout=timeout + 10, # Extra time for docker overhead
                        env=env
                    )
                    
                    # If docker command itself failed (e.g. daemon not running), fallback to local
                    if result.returncode != 0 and ("docker daemon" in result.stderr.lower() or "connect" in result.stderr.lower()):
                        log.debug("Docker daemon not reachable, falling back to local execution")
                    else:
                        output = result.stdout
                        if result.stderr:
                            output += f"\n[STDERR]\n{result.stderr}"
                        return result.returncode == 0, output.strip()
                except subprocess.TimeoutExpired:
                    return False, "Docker Execution timed out."
                except Exception:
                    # If docker fails, fallback to local
                    pass

            # Fallback to local subprocess execution
            result = subprocess.run(
                [sys.executable, temp_path],
                capture_output=True,
                text=True,
                encoding='utf-8',
                timeout=timeout,
                env=env
            )
            output = result.stdout
            if result.stderr:
                output += f"\n[STDERR]\n{result.stderr}"
            return result.returncode == 0, output.strip()

        except subprocess.TimeoutExpired:
            return False, "Execution timed out (infinite loop or hanging process)"
        except Exception as e:
            return False, f"Sandbox error: {str(e)}"
        finally:
            try:
                os.remove(temp_path)
            except OSError:
                pass
