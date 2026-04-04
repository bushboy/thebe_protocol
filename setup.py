"""Setup configuration for Zero-Trust Agentic Guardian Architecture."""

from setuptools import setup, find_packages

setup(
    name="zero-trust-agentic-guardian",
    version="0.1.0",
    description="Zero-Trust Agentic Guardian Architecture",
    author="Your Name",
    author_email="your.email@example.com",
    packages=find_packages(exclude=["tests*"]),
    python_requires=">=3.14.2,<3.15",
    install_requires=[
        "fastapi>=0.109.0",
        "uvicorn[standard]>=0.27.0",
        "httpx>=0.26.0",
        "hypothesis>=6.98.0",
        "pytest>=8.0.0",
        "pytest-asyncio>=0.23.5",
        "PyJWT>=2.8.0",
        "cryptography>=42.0.0",
        "sentence-transformers>=2.3.1",
        "pydantic>=2.12.5",
        "pydantic-settings>=2.13.1",
        "psycopg2-binary>=2.9.9",
        "redis>=5.0.1",
        "requests>=2.31.0",
        "PyGithub>=2.1.1",
        "slack-sdk>=3.26.2",
        "google-api-python-client>=2.116.0",
        "boto3>=1.34.0",
        "python-dotenv>=1.0.1",
    ],
    extras_require={
        "dev": [
            "black>=24.0.0",
            "flake8>=7.0.0",
            "mypy>=1.8.0",
        ]
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3.14",
    ],
)
