#!/usr/local/bin/bash
#################################################################################
# Receive a file containing AS numbers and produce an output
# AS_CONE_OUTPUT:   AS   AS_CONE   IP_ADDRESS
#################################################################################

###############################################################################
### Program settings
shopt -s expand_aliases
alias utc='date -u +%s'

INFILE="ixsp-comm-list.txt"
OUTFILE="ixsp-ascone-list.txt"
TMPFILE="ascone.$$.tmp"


###############################################################################
### Functions
client_cone(){
	local ASN=$1

	#original query from https://api.asrank.caida.org/v2/docs
	#curl -H "Content-Type: application/json" -X POST --data '{ "query": "{ asn(asn:\"2716\"){ asn organization { orgName } cone { numberAsns,numberAddresses } } }" }' https://api.asrank.caida.org/v2/graphql

	#query="asn(asn:\"" $ASN "\"){ asn organization{orgName} cone{numberAsns,numberAddresses} }"
	query="asn(asn:\\\""
	query+=$ASN 
	query+="\\\"){ asn organization{orgName} cone{numberAsns,numberAddresses} }"
	#echo "QUERY = [$query]"

	#declare -a cmd
	cmd="curl -ss -H \"Content-Type: application/json\"  -X POST --data "
	cmd+="'{ \"query\": \"{ $query }\" }' "
	cmd+="https://api.asrank.caida.org/v2/graphql "
	#cmd+="2>/dev/null"
	#echo "COMMAND = $cmd"

	#asrank="$(curl -ss -H "Content-Type: application/json" -X POST --data '{ "query": $query }' https://api.asrank.caida.org/v2/graphql 2>/dev/null)"
	asrank=`eval $cmd`
	#echo "asrank ($asrank)"
	asorg=$( echo $asrank | jq .data.asn.organization.orgName)
	ascone=$( echo $asrank | jq .data.asn.cone.numberAsns)
	addcone=$( echo $asrank | jq .data.asn.cone.numberAddresses)

  # To remove quotes
  temp="${asorg%\"}"
  temp="${temp#\"}"
 
	#AS_CONE_OUTPUT=`echo -e "$ASN:$ascone:$addcone:$temp"`
	AS_CONE_OUTPUT=`echo -e "$ASN\t$ascone\t$addcone\t\t$asorg"`
	echo "$AS_CONE_OUTPUT"	
}

###############################################################################
### MAIN
###############################################################################
echo > $TMPFILE
echo > $OUTFILE
while IFS=':' read -r COMM ASN
do 
    #echo "(ASN, $ASN, $COMM)"
    client_cone $ASN
    echo $AS_CONE_OUTPUT >> $TMPFILE
done <$INFILE

cat $TMPFILE | grep -v null | sort  -u | sort -n -r -k3 > $OUTFILE

# End  of  program

