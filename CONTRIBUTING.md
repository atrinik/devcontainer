# Contributing

Use a Conventional Commits pull-request title and run the image checks
documented in `README.md`. Keep image inputs reproducible and avoid embedding
credentials or host-specific state. Every squash merge releases the broad
Linux, slim Classic, and Windows images, so changes must leave both publishing
workflows valid even when only one Dockerfile is edited.
