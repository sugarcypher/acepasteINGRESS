/**
 * Popular package names, for the lookalike check in `ingress pkgcheck`. Built in and never fetched: a few
 * hundred of the most-installed names per ecosystem, written down by hand from public download rankings
 * (npm weekly downloads, PyPI's top-packages lists) in November 2026. The list does not need to be exact or
 * current; it needs to hold the names worth imitating.
 */

export const NPM_TOP: readonly string[] = [
  // frameworks and UI
  "react", "react-dom", "react-router", "react-router-dom", "react-redux", "redux", "@reduxjs/toolkit", "redux-thunk", "redux-saga",
  "vue", "vue-router", "vuex", "pinia", "nuxt", "svelte", "@sveltejs/kit", "angular", "@angular/core", "@angular/common", "@angular/cli",
  "next", "gatsby", "preact", "solid-js", "lit", "jquery", "backbone", "ember-source", "alpinejs", "htmx.org",
  "react-native", "expo", "electron", "react-query", "@tanstack/react-query", "swr", "zustand", "mobx", "jotai", "recoil", "immer",
  "styled-components", "@emotion/react", "@emotion/styled", "tailwindcss", "postcss", "autoprefixer", "sass", "less", "bootstrap",
  "@mui/material", "antd", "classnames", "clsx", "framer-motion", "react-hook-form", "formik", "yup", "zod", "joi", "ajv",
  "react-icons", "@fortawesome/fontawesome-svg-core", "chart.js", "d3", "three", "leaflet", "react-select", "react-table", "@headlessui/react",
  // build and tooling
  "typescript", "webpack", "webpack-cli", "webpack-dev-server", "vite", "rollup", "esbuild", "parcel", "@babel/core", "@babel/preset-env",
  "@babel/preset-react", "@babel/runtime", "babel-loader", "ts-loader", "ts-node", "tsx", "tsup", "swc", "@swc/core", "terser", "uglify-js",
  "css-loader", "style-loader", "sass-loader", "file-loader", "url-loader", "html-webpack-plugin", "mini-css-extract-plugin", "copy-webpack-plugin",
  "eslint", "prettier", "eslint-config-prettier", "eslint-plugin-react", "eslint-plugin-import", "@typescript-eslint/parser", "@typescript-eslint/eslint-plugin",
  "eslint-plugin-react-hooks", "stylelint", "husky", "lint-staged", "nodemon", "concurrently", "cross-env", "rimraf", "npm-run-all", "turbo", "nx", "lerna",
  "jest", "mocha", "chai", "sinon", "vitest", "jasmine", "karma", "ava", "tap", "supertest", "nock", "cypress", "playwright", "@playwright/test",
  "puppeteer", "selenium-webdriver", "@testing-library/react", "@testing-library/jest-dom", "enzyme", "ts-jest", "babel-jest", "c8", "nyc", "istanbul",
  "storybook", "@storybook/react", "semantic-release", "standard-version", "np", "patch-package", "npm", "yarn", "pnpm", "corepack",
  // server and network
  "express", "koa", "fastify", "hapi", "@hapi/hapi", "restify", "nest", "@nestjs/core", "@nestjs/common", "socket.io", "socket.io-client", "ws",
  "axios", "node-fetch", "got", "request", "superagent", "undici", "cross-fetch", "isomorphic-fetch", "ky", "http-proxy", "http-proxy-middleware",
  "body-parser", "cookie-parser", "cors", "helmet", "morgan", "compression", "express-session", "passport", "passport-local", "passport-jwt",
  "jsonwebtoken", "bcrypt", "bcryptjs", "argon2", "multer", "busboy", "formidable", "connect", "serve-static", "serve", "http-server", "live-server",
  "graphql", "apollo-server", "@apollo/client", "graphql-tag", "graphql-request", "@trpc/server", "grpc", "@grpc/grpc-js", "protobufjs",
  // data and databases
  "mongoose", "mongodb", "mysql", "mysql2", "pg", "sqlite3", "better-sqlite3", "sequelize", "typeorm", "prisma", "@prisma/client", "knex",
  "redis", "ioredis", "drizzle-orm", "firebase", "firebase-admin", "@supabase/supabase-js", "aws-sdk", "@aws-sdk/client-s3", "@google-cloud/storage",
  "stripe", "twilio", "@sendgrid/mail", "nodemailer", "openai", "@anthropic-ai/sdk", "langchain", "@langchain/core", "ai", "@modelcontextprotocol/sdk",
  // utilities
  "lodash", "lodash-es", "underscore", "ramda", "moment", "moment-timezone", "dayjs", "date-fns", "luxon", "uuid", "nanoid", "shortid",
  "chalk", "colors", "picocolors", "kleur", "ansi-styles", "debug", "commander", "yargs", "minimist", "meow", "inquirer", "prompts", "ora", "listr",
  "dotenv", "config", "cosmiconfig", "rc", "fs-extra", "graceful-fs", "glob", "globby", "fast-glob", "minimatch", "micromatch", "chokidar",
  "mkdirp", "del", "tmp", "semver", "async", "bluebird", "p-limit", "p-queue", "rxjs", "eventemitter3", "events", "core-js", "regenerator-runtime",
  "tslib", "@types/node", "@types/react", "@types/express", "@types/jest", "@types/lodash", "qs", "query-string", "path-to-regexp", "url-parse",
  "cheerio", "jsdom", "htmlparser2", "marked", "markdown-it", "highlight.js", "prismjs", "handlebars", "ejs", "pug", "mustache", "nunjucks",
  "xml2js", "fast-xml-parser", "yaml", "js-yaml", "csv-parse", "papaparse", "xlsx", "pdfkit", "sharp", "jimp", "canvas", "archiver", "jszip",
  "adm-zip", "tar", "node-gyp", "bindings", "nan", "node-addon-api", "prebuild-install", "cross-spawn", "execa", "shelljs", "which", "open",
  "winston", "pino", "bunyan", "log4js", "loglevel", "validator", "crypto-js", "bn.js", "big.js", "decimal.js", "ethers", "web3", "buffer",
  "readable-stream", "through2", "split2", "pump", "once", "inherits", "safe-buffer", "string_decoder", "iconv-lite", "mime", "mime-types",
  "form-data", "follow-redirects", "proxy-from-env", "agent-base", "https-proxy-agent", "socks-proxy-agent", "tough-cookie", "punycode",
  "deepmerge", "deep-equal", "fast-deep-equal", "object-assign", "is-number", "kind-of", "isarray", "escape-string-regexp", "strip-ansi",
  "string-width", "wrap-ansi", "cli-table3", "boxen", "figlet", "progress", "cli-progress", "update-notifier", "node-cron", "cron", "bull", "bullmq",
  "sharp-cli", "nodemailer-smtp-transport", "puppeteer-core", "electron-builder", "esm", "source-map", "source-map-support", "acorn", "estraverse",
  "event-stream", "left-pad", "ua-parser-js", "coa", "rc-config-loader", "node-ipc", "faker", "@faker-js/faker", "colorette", "signal-exit",
];

export const PYPI_TOP: readonly string[] = [
  // packaging and the base
  "pip", "setuptools", "wheel", "packaging", "six", "certifi", "urllib3", "idna", "charset-normalizer", "chardet", "requests", "typing-extensions",
  "python-dateutil", "pytz", "tzdata", "attrs", "pyyaml", "toml", "tomli", "tomlkit", "filelock", "platformdirs", "virtualenv", "distlib",
  "importlib-metadata", "zipp", "pyparsing", "cffi", "pycparser", "cryptography", "pyopenssl", "rsa", "pyasn1", "pyasn1-modules", "jmespath",
  "markupsafe", "jinja2", "click", "colorama", "rich", "tqdm", "wrapt", "decorator", "more-itertools", "cachetools", "pluggy", "iniconfig",
  "exceptiongroup", "annotated-types", "pydantic", "pydantic-core", "pydantic-settings", "python-dotenv", "dataclasses-json", "marshmallow",
  // web and network
  "flask", "django", "fastapi", "starlette", "uvicorn", "gunicorn", "werkzeug", "itsdangerous", "aiohttp", "httpx", "httpcore", "h11", "anyio",
  "sniffio", "websockets", "websocket-client", "requests-oauthlib", "oauthlib", "requests-toolbelt", "grpcio", "grpcio-tools", "protobuf",
  "tornado", "sanic", "bottle", "pyramid", "falcon", "quart", "celery", "kombu", "redis", "pika", "paramiko", "fabric", "scrapy", "beautifulsoup4",
  "lxml", "html5lib", "soupsieve", "selenium", "playwright", "mechanize", "pyjwt", "python-jose", "passlib", "bcrypt", "argon2-cffi", "authlib",
  "djangorestframework", "django-cors-headers", "flask-sqlalchemy", "flask-cors", "flask-login", "flask-wtf", "wtforms", "graphene", "strawberry-graphql",
  // data and science
  "numpy", "pandas", "scipy", "matplotlib", "seaborn", "plotly", "bokeh", "altair", "scikit-learn", "scikit-image", "statsmodels", "sympy",
  "networkx", "pillow", "opencv-python", "opencv-python-headless", "imageio", "pyarrow", "polars", "dask", "numba", "xarray", "h5py", "tables",
  "openpyxl", "xlrd", "xlsxwriter", "tabulate", "sqlalchemy", "alembic", "psycopg2", "psycopg2-binary", "psycopg", "pymysql", "mysqlclient",
  "pymongo", "motor", "elasticsearch", "cassandra-driver", "boto3", "botocore", "s3transfer", "awscli", "google-cloud-storage", "google-api-core",
  "google-auth", "google-api-python-client", "azure-core", "azure-storage-blob", "azure-identity", "jupyter", "jupyterlab", "notebook", "ipython",
  "ipykernel", "ipywidgets", "nbformat", "nbconvert", "streamlit", "gradio", "dash", "shap", "xgboost", "lightgbm", "catboost", "optuna",
  // machine learning and AI
  "torch", "torchvision", "torchaudio", "tensorflow", "keras", "jax", "jaxlib", "transformers", "tokenizers", "datasets", "accelerate",
  "huggingface-hub", "safetensors", "sentence-transformers", "diffusers", "peft", "bitsandbytes", "onnx", "onnxruntime", "openai", "anthropic",
  "langchain", "langchain-core", "langchain-community", "langchain-openai", "llama-index", "tiktoken", "sentencepiece", "nltk", "spacy", "gensim",
  "faiss-cpu", "chromadb", "pinecone-client", "weaviate-client", "qdrant-client", "litellm", "instructor", "mcp", "fastmcp", "vllm", "ollama",
  // tooling and testing
  "pytest", "pytest-cov", "pytest-mock", "pytest-asyncio", "pytest-xdist", "coverage", "tox", "nox", "mock", "hypothesis", "faker", "factory-boy",
  "black", "isort", "flake8", "pylint", "mypy", "ruff", "autopep8", "yapf", "pycodestyle", "pyflakes", "bandit", "pre-commit", "poetry",
  "poetry-core", "hatchling", "flit-core", "build", "twine", "pipenv", "pipx", "uv", "conda", "sphinx", "mkdocs", "mkdocs-material", "docutils",
  "invoke", "typer", "fire", "docopt", "loguru", "structlog", "sentry-sdk", "prometheus-client", "psutil", "watchdog", "schedule", "apscheduler",
  "pexpect", "ptyprocess", "sh", "plumbum", "docker", "kubernetes", "ansible", "ansible-core", "pywin32", "pyinstaller", "cython", "pybind11",
  "msgpack", "orjson", "ujson", "simplejson", "jsonschema", "python-multipart", "email-validator", "pycryptodome", "pynacl", "ecdsa", "web3",
  "arrow", "pendulum", "humanize", "regex", "unidecode", "emoji", "markdown", "mistune", "pygments", "prompt-toolkit", "questionary", "inquirer",
  "pyserial", "pyusb", "pygame", "kivy", "pyqt5", "pyside6", "tk", "wxpython", "discord.py", "python-telegram-bot", "slack-sdk", "tweepy",
  "stripe", "twilio", "sendgrid", "types-requests", "types-pyyaml", "setuptools-scm", "colorlog", "termcolor", "art", "pyfiglet",
];
