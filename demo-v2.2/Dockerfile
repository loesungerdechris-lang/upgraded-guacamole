# Optional packaging of the already compiled, tested static executable.
# The canonical runner uses Crane to package the same single-file layer.
FROM scratch
COPY .run/sentinel-demo /sentinel-demo
ENTRYPOINT ["/sentinel-demo"]
