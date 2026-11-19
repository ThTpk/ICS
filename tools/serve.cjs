const http=require('http'),fs=require('fs'),path=require('path');
const root=process.cwd(), port=5173;
const T={'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8','.svg':'image/svg+xml','.json':'application/json'};
http.createServer((req,res)=>{
  let p=decodeURIComponent(req.url.split('?')[0]);
  if(p==='/')p='/index.html';
  const f=path.join(root,p);
  if(!f.startsWith(root)){res.writeHead(403);return res.end();}
  fs.readFile(f,(e,d)=>{
    if(e){res.writeHead(404,{'content-type':'text/plain'});return res.end('404 '+p);}
    res.writeHead(200,{'content-type':T[path.extname(f)]||'application/octet-stream','cache-control':'no-store'});
    res.end(d);
  });
}).listen(port,()=>console.log('serving '+root+' on http://localhost:'+port));
