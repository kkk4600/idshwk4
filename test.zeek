@load base/frameworks/sumstats

global codeTable:table[count] of int=table();
global urllist:set[string];
global url:string;
global uuc:count=0;

event zeek_init()
{
local r1=SumStats::Reducer($stream="404.sum",$apply=set(SumStats::SUM));#看一共有几个404
local r2=SumStats::Reducer($stream="response.sum",$apply=set(SumStats::SUM));#看一共有多少response
SumStats::create([$name="404response",
$epoch=10min,
$reducers=set(r1),
$reducers=set(r2),
$epoch_result(ts:time, key:SumStats::Key, result:SumStats::Result) =
{
local rst1=result["404.sum"];
local rst2=result["response.sum"];
if(rst1$num>2){
if(rst1$num/rst2$num>0.2){
if(uuc/rst1$num>0.5){
print fmt("%s is a scanner with %d scan attemps on %d urls",key$host, rst1$num, uuc);
}
}
}
}]);
}
