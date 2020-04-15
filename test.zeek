@load base/frameworks/sumstats

global codeTable:table[count] of int=table();
global urllist:set[string];
global url:string;
global uuc:count=0;
global num1:count=0;

event zeek_init()
{
local r1=SumStats::Reducer($stream="404.sum",$apply=set(SumStats::SUM));#看一共有几个404
local r2=SumStats::Reducer($stream="response.sum",$apply=set(SumStats::SUM));#看一共有多少response
SumStats::create([$name="404response",
$epoch=10min,
$reducers=set(r1),
$epoch_result(ts:time, key:SumStats::Key, result:SumStats::Result) =
{
local rst1=result["404.sum"];
num1=rst1$num;
},
$reducers=set(r2),
$epoch_result(ts:time, key:SumStats::Key, result:SumStats::Result) =
{
local rst2=result["response.sum"];
if(num1>2){
if(rst2$num*0.2<num1){
if(num1*0.5<uuc){
print fmt("%s is a scanner with %d scan attemps on %d urls",key$host,num1,uuc);
}
}
}
}]);
}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
{
url=unescaped_URI;
}
event http_reply(c: connection, version: string, code: count, reason: string)
{
SumStats::observe("response.sum",[$host=c$id$orig_h],[$num=1]);
if(code==404){
SumStats::observe("404.sum",[$host=c$id$orig_h],[$num=1]);
if(url !in urllist) uuc+=1;
}
}
