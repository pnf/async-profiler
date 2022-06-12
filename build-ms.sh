#!/ms/dist/fsf/PROJ/bash/4.3/bin/bash -vx                              

AUTOCONF=/ms/dist/fsf/PROJ/autoconf/2.69-0/bin

if [ "$ID_EXEC" = "x86_64.linux.2.6.glibc.2.17" ]; then
    TOOLS=/ms/dist/mstk/PROJ/rhdevtoolset/9.1-rhel7-0/bin/
elif [ "$ID_EXEC" = "x86_64.linux.2.6.glibc.2.12" ]; then
    TOOLS=/ms/dist/mstk/PROJ/rhdevtoolset/8.0-rhel6-0/bin/
else
    echo No good gcc found
    exit 1
fi


export PATH=$AUTOCONF:$TOOLS:$PATH

make clean
JAVA_HOME=/ms/dist/msjava/PROJ/azulzulu-openjdk/11.0.6.1ms make

C=../install/common
E=../install/.exec/$ID_KVM

mkdir -p $C/lib $E/bin $E/lib $E/bin/build

cp build/lib/*.jar $C/lib
cp -p build/lib/*.so $E/lib
cp -p build/bin/asprof $E/bin

# The shell script expects to find its companions in a build subdirectory
cd $E/bin/build
ln -fs ../../lib/libasyncProfiler.so
ln -fs ../asprof
