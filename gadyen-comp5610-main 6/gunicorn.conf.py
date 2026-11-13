"""Gunicorn settings for the gadyen_web interface (loaded automatically when
gunicorn starts in this folder).

- timeout: the AI agent can take longer than gunicorn's default 30 s; without
  this the worker is killed mid-answer and the chat shows an error.
- one worker + threads: live chat sessions are kept in memory, so every
  request from a user must reach the same process.
"""
timeout = 120
workers = 1
threads = 8
