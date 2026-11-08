<?php
/** Native process/file-lock checks; no WordPress/site bootstrap. */
if (($argv[1] ?? '') === '--child') {
    ini_set('display_errors', '0'); ini_set('log_errors', '0');
    $root = $argv[2]; $mode = $argv[3]; $id = $argv[4];
    define('ABSPATH', $root . '/web/'); define('DOING_CRON', $mode !== 'page');
    define('WORDPRIIS_CRON_GATE_HASH', hash('sha256', str_repeat('a', 64)));
    define('WORDPRIIS_CRON_GATE_LOCK', $root . ($mode === 'missing' ? '/absent' : '/cron.lock'));
    define('WORDPRIIS_CRON_GATE_RESULT', $root . '/result.json');
    define('WORDPRIIS_CRON_GATE_RUNS', $root . '/runs');
    $_GET = ['wordpriis_cron_run' => $id, 'wordpriis_cron_phase' => 'normal'];
    $_SERVER['HTTP_X_WORDPRIIS_PROFILE'] = str_repeat('a', 64);
    require __DIR__ . '/../scripts/cron-gate.php';
    file_put_contents($root . '/admitted-' . $id, 'ok');
    if ($mode === 'hold') { usleep(1200000); }
    if ($mode === 'fatal') { WORDPRIIS_SECRET_UNDEFINED_CALLBACK(); }
    exit;
}
$n=0;$check=static function($ok,$name)use(&$n){if(!$ok){throw new RuntimeException($name);}$n++;};
$root=sys_get_temp_dir().'/wordpriis-cron-gate-'.bin2hex(random_bytes(8));mkdir($root);mkdir($root.'/web');mkdir($root.'/runs');touch($root.'/cron.lock');touch($root.'/result.json');
$start=static function($mode,$id)use($root){$p=proc_open([PHP_BINARY,__FILE__,'--child',$root,$mode,$id],[1=>['pipe','w'],2=>['pipe','w']],$pipes);return [$p,$pipes];};
$finish=static function($process){[$p,$pipes]=$process;$out=stream_get_contents($pipes[1]);$err=stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);return [proc_close($p),$out,$err];};
try{
 $a=str_repeat('a',32);$b=str_repeat('b',32);$one=$start('hold',$a);
 $until=microtime(true)+5;while(!file_exists($root.'/admitted-'.$a)&&microtime(true)<$until){usleep(10000);}
 $check(file_exists($root.'/admitted-'.$a),'first cron admitted');
 $two=$finish($start('normal',$b));$busy=json_decode(file_get_contents($root.'/result.json'),true);
 $check($two===[0,'','']&&!file_exists($root.'/admitted-'.$b),'second cron never executes while lock held');
 $check($busy['run_id']===$b&&$busy['status']==='busy','busy marker belongs to rejected run');
 $first=$finish($one);$done=json_decode(file_get_contents($root.'/result.json'),true);
 $check(json_decode(file_get_contents($root.'/runs/'.$b.'.json'),true)['status']==='busy','per-run receipt survives another run completion');
 $check($first===[0,'','']&&$done['run_id']===$a&&$done['status']==='complete','completion only after first PHP job ends');
 $third=$finish($start('normal',$b));
 $check($third===[0,'','']&&file_exists($root.'/admitted-'.$b),'lock released for next run');
 $c=str_repeat('c',32);$fatal=$finish($start('fatal',$c));$failed=json_decode(file_get_contents($root.'/result.json'),true);
 $check($fatal[0]!==0&&$failed['status']==='failed'&&$failed['reason']==='php-fatal','fatal PHP reports failure after early response');
 $check(!str_contains(json_encode($failed),'SECRET')&&!str_contains(json_encode($failed),$root),'no fatal message or path exported');
 $missing=$finish($start('missing',str_repeat('d',32)));$failed=json_decode(file_get_contents($root.'/result.json'),true);
 $check($missing===[0,'','']&&$failed['reason']==='lock-open-failed','missing private lock cannot claim a successful task');
 $before=file_get_contents($root.'/result.json');$page=$finish($start('page',str_repeat('e',32)));
 $check($page===[0,'','']&&file_get_contents($root.'/result.json')===$before,'normal page neither locks nor records cron status');
}finally{foreach(glob($root.'/runs/*')as$file){unlink($file);}rmdir($root.'/runs');foreach(glob($root.'/*')as$file){if(is_file($file)){unlink($file);}}rmdir($root.'/web');rmdir($root);}
echo "Cron gate: {$n} assertions passed.\n";
