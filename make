 gcc -O2 -Wall -Wextra -Werror -std=c99 -DKYBER_K=4 -I. -Ikyber \
     axis.c intern.c \
     kyber/cbd.c kyber/fips202.c kyber/indcpa.c kyber/kem.c \
     kyber/ntt.c kyber/poly.c kyber/polyvec.c kyber/reduce.c \
     kyber/symmetric-shake.c kyber/verify.c \
     -DOPENSSLDIR="\"/dev/null\"" \
     -DENGINESDIR="\"/dev/null\"" \
     -DMODULESDIR="\"/dev/null\"" \
     -fPIE -pie -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
     -fno-builtin-memset -fno-strict-aliasing -DAXIS_KECCAK_ONLY\
     -Wl,-z,relro,-z,now \
     -Wl,-Bstatic -lcrypto -lsodium -Wl,-Bdynamic \
     -latomic -lpthread -ldl -lm -lc \
     -s -o axis
