FROM debian:testing

ENV DEBIAN_FRONTEND=noninteractive
RUN apt update && apt install -y llvm-14 clang-14 clang cmake flex bison bc libelf-dev libssl-dev
ADD ktypes.cpp CMakeLists.txt actor_static.config /plugin/
WORKDIR /plugin/
RUN mkdir build && cd build && cmake .. && make

RUN echo "clang-14 -g -fexperimental-new-pass-manager -fpass-plugin=/plugin/build/libktypesPass.so \"\$@\"" > /bin/clang-ktypes && chmod +x /bin/clang-ktypes
CMD make -C /kernel/ -j `nproc` CC=clang-ktypes
