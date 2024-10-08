dotnet pack --output "Packages" --include-symbols -c Release -p:PackageVersion=${3}
if [[ ${?} != 0 ]]
then 
	exit -1
fi

echo 'Publishing packages'

cd Packages
for file in *; do 
	if [[ ${file} == *${3}.symbols.nupkg ]]
	then
		dotnet nuget push -s ${1} -k ${2} ${file}
        	if [[ ${?} != 0  ]]
        	then
        	    exit -1
        	fi
		sleep 1
	fi
done
