# Image gateway = LiteLLM gốc + pypdf (để gate_masker lấy chữ trong PDF ra quét).
# Không sửa gì trong LiteLLM: pypdf (thuần Python, không phụ thuộc thêm) cài vào /opt/gate-vendor ở một bước riêng,
# rồi chỉ chép thư mục đó sang. gate_masker.py tự thêm /opt/gate-vendor vào sys.path.
#
# Chuỗi cung ứng: chốt phiên bản cả hai image và pypdf. Sau lần build đầu, thay tag bằng digest
# (docker image inspect <image> --format '{{index .RepoDigests 0}}'), và thêm --hash=sha256:<...> cho pypdf
# (lấy trên https://pypi.org/project/pypdf/6.17.0/#files) rồi đổi --no-deps thành --require-hashes --no-deps.
ARG LITELLM_IMAGE=ghcr.io/berriai/litellm:v1.106.7
ARG PYTHON_IMAGE=python:3.12-slim

FROM ${PYTHON_IMAGE} AS pdfdeps
RUN pip install --no-cache-dir --no-deps --target /vendor "pypdf==6.17.0"

FROM ${LITELLM_IMAGE}
COPY --from=pdfdeps /vendor /opt/gate-vendor
