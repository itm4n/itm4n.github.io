# Use latest Ubuntu image
FROM ubuntu:latest
# Install ruby and its dependencies + git
ENV DEBIAN_FRONTEND=noninteractive
RUN apt update && apt install -y ruby-full build-essential zlib1g-dev git
# Install Jekyll and its dependencies
RUN gem install jekyll jekyll-feed jemoji bundler
