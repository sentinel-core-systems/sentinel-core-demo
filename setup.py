from setuptools import setup, find_packages

setup(
    name="sentinel-core",
    version="2.0.0",
    author="Sentinel Security",
    author_email="support@sentinel.security",
    description="Deterministic Security Gate for CI/CD, IaC, and Supply Chain Integrity",
    long_description="A professional security tool designed to enforce policies in automated pipelines.",
    long_description_content_type="text/markdown",
    url="https://github.com/<YOUR_ORGANIZATION_OR_USERNAME> # FIXME: Replace with your actual GitHub Org/User/<YOUR_PRIVATE_REPO_NAME>",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "": ["*.yaml", "*.yml", "*.json", "*.py"],
        "sentinel": [
            "*.yaml", "*.yml", "*.json",
            "rules/**/*.py",
            "universal_logic.json",
        ],
        "auditor": [
            "*.yaml", "*.yml", "*.json",
            "resources/*.json",
            "resources/*.yaml",
            "rules/*.yaml",
        ],
    },
    install_requires=[
        "click==8.1.7",
        "pyyaml==6.0.1",
        "requests==2.31.0",
        "openai==2.15.0",
        "python-dotenv>=1.0.0",
        "pydantic>=2.5.3",
        "pydantic-settings>=2.1.0",
        "cryptography>=42.0.0",
        "jinja2>=3.1.3",
        "python-magic>=0.4.27",
        "httpx>=0.26.0",
        "tqdm>=4.66.0",
        "groq>=1.0.0",
        "bandit>=1.7.6",
    ],
    entry_points={
        "console_scripts": [
            "sentinel=sentinel.main:cli",
        ],
    },
    python_requires=">=3.10",
    zip_safe=False,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: Other/Proprietary License",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
)
