if [ "$ID_EXEC" = "x86_64.linux.2.6.glibc.2.17" ]; then
    TOOLS=/ms/dist/mstk/PROJ/rhdevtoolset/9.1-rhel7-0/bin/
elif [ "$ID_EXEC" = "x86_64.linux.2.6.glibc.2.12" ]; then
    TOOLS=/ms/dist/mstk/PROJ/rhdevtoolset/8.0-rhel6-0/bin/
elif [ "$ID_EXEC" = "x86_64.linux.2.6.glibc.2.28" ]; then
    TOOLS=/ms/dist/mstk/PROJ/rhdevtoolset/9.0-rhel8-1/bin
else
    echo No good gcc found
    exit 1
fi


export PATH=$TOOLS:$PATH
export JAVA_HOME=/ms/dist/msjava/PROJ/azulzulu-openjdk/21.0.9_21.46.22
#export JAVA_HOME=/ms/dist/msjava/PROJ/azulzulu-openjdk/11.0.6.1ms

# The env.sh file can be read in a clion toolchain definition.
echo export PATH=$PATH > env.sh
echo export JAVA_HOME=$JAVA_HOME >> env.sh
export SKIP=$SKIP >> env.sh

