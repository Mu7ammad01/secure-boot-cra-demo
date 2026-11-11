# Stand-in de la signature CSF : signe les images deployees en fin de build (cle HORS depot, via LAB_SIGN_KEY).
# Montre OU se branche la signature dans le build ; sur i.MX8M ce serait cst + srktool sur imx-boot.
LAB_SIGN_KEY ?= ""
LAB_SIGN_GLOB ?= "${IMAGE_BASENAME}-${MACHINE}*.ext4"

do_lab_sign() {
    if [ -z "${LAB_SIGN_KEY}" ] || [ ! -f "${LAB_SIGN_KEY}" ]; then
        bbfatal "LAB_SIGN_KEY absente : la cle de signature doit exister et rester hors depot"
    fi
    cd "${DEPLOY_DIR_IMAGE}"
    found=0
    for f in ${LAB_SIGN_GLOB}; do
        [ -f "$f" ] || continue
        openssl dgst -sha256 -sign "${LAB_SIGN_KEY}" -out "$f.sig" "$f"
        bbnote "signe : $f"
        found=1
    done
    [ "$found" = 1 ] || bbwarn "lab-sign : aucun fichier ne correspond a ${LAB_SIGN_GLOB}"
}
addtask lab_sign after do_image_complete before do_build
