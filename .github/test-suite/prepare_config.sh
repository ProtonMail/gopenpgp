CONFIG_TEMPLATE=$1
CONFIG_OUTPUT=$2
GOSOP_BRANCH=$3
GOSOP_TARGET=$4
cat $CONFIG_TEMPLATE \
    | sed "s@__GOSOP_BRANCH__@${GOSOP_BRANCH}@g" \
    | sed "s@__GOSOP_TARGET__@${GOSOP_TARGET}@g" \
    | sed "s@__SQOP__@${SQOP}@g" \
    | sed "s@__GPGME_SOP__@${GPGME_SOP}@g" \
    | sed "s@__SOP_OPENPGPJS__@${SOP_OPENPGPJS_V2}@g" \
    | sed "s@__RNP_SOP__@${RNP_SOP}@g" \
    > $CONFIG_OUTPUT