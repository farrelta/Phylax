"""Escaped native controls and bounded navigation shared by operator views."""
import html
import json
from urllib.parse import urlencode, urlsplit


def e(value):
    return html.escape(str(value),quote=True)


def hidden(name,value):
    return f'<input type="hidden" name="{e(name)}" value="{e(value)}">'


def field(name,label,value='',required=False,kind='text',*,maxlength=4000,control_id='',help_text='',error=''):
    described=' '.join(control_id+suffix for suffix,text in (('-help',help_text),('-error',error)) if text and control_id)
    attrs=(f' id="{e(control_id)}"' if control_id else '')
    if control_id:attrs+=f' aria-labelledby="{e(control_id)}-label"'
    if described:attrs+=f' aria-describedby="{e(described)}"'
    if error:attrs+=' aria-invalid="true"'
    help_html=f'<small id="{e(control_id)}-help">{e(help_text)}</small>' if help_text else ''
    error_html=f'<small class="field-error" id="{e(control_id)}-error">{e(error)}</small>' if error else ''
    label_html=f'<span id="{e(control_id)}-label">{e(label)}</span>' if control_id else e(label)
    return (f'<label>{label_html}<input type="{e(kind)}" name="{e(name)}" value="{e(value)}" maxlength="{int(maxlength)}"{attrs}'
            +(' required' if required else '')+'>'+help_html+error_html+'</label>')


def select(name,label,choices,selected=None):
    return f'<label>{e(label)}<select name="{e(name)}">'+''.join(
        f'<option value="{e(value)}"'+(' selected' if str(value)==str(selected) else '')+f'>{e(text)}</option>'
        for value,text in choices)+'</select></label>'


def form(path,body,label):
    return f'<form method="post" action="{e(path)}">{body}<button>{e(label)}</button></form>'


def actor_fields(values=None):
    values=values or {}
    return field('actor','Operator name',values.get('actor',''),True)+field('note','Decision / evidence note',values.get('note',''),True)


def error_summary(message,links=()):
    items=''.join('<li><a href="#'+e(target)+'">'+e(label)+'</a></li>' for target,label in links)
    return ('<section class="notice error error-summary" id="input-errors" role="alert" tabindex="-1" autofocus>'
            '<h2>Changes were not saved</h2><p>'+e(message)+'</p>'
            +('<ul>'+items+'</ul>' if items else '')
            +'<p>Your entries are retained below. Correct the values and retry.</p></section>')


def table(rows,columns,actions=None,empty='No records yet.'):
    body=''
    for row in rows:
        cells=''.join('<td>'+e(json.dumps(row.get(key),ensure_ascii=False) if isinstance(row.get(key),(list,dict))
                            else row.get(key,''))+'</td>' for key,label in columns)
        if actions:cells+='<td>'+actions(row)+'</td>'
        body+='<tr>'+cells+'</tr>'
    headings=''.join('<th scope="col">'+e(label)+'</th>' for key,label in columns)
    if actions:headings+='<th scope="col">Actions</th>'
    return ('<section class="panel"><table><thead><tr>'+headings+'</tr></thead><tbody>'
            +(body or f'<tr><td colspan="{len(columns)+bool(actions)}" class="empty">{e(empty)}</td></tr>')+'</tbody></table></section>')


def pager(path,query,number,total,size=50):
    if total<=size and number==1:return ''
    values={k:v[0] for k,v in query.items() if v and k!='page'}
    def link(page,label):return '<a href="'+e(path+'?'+urlencode({**values,'page':page}))+'">'+label+'</a>'
    links=[]
    if number>1:links.append(link(number-1,'Previous'))
    links.append(f'<span>Page {number} · {total} records</span>')
    if number*size<total:links.append(link(number+1,'Next'))
    return '<nav class="pagination" aria-label="Result pages">'+' '.join(links)+'</nav>'


def raw_record(value,label='Raw record'):
    return '<details class="raw-record"><summary>'+e(label)+'</summary><pre>'+e(json.dumps(value,indent=2,ensure_ascii=False))+'</pre></details>'


def reference_links(values):
    """Link public HTTP references; keep unsupported/untrusted schemes inert."""
    links=[]
    for value in values:
        value=str(value)
        try:
            parsed=urlsplit(value)
            valid=parsed.scheme in {'http','https'} and bool(parsed.hostname) and not parsed.username and not parsed.password
        except ValueError:
            valid=False
        if valid and not any(ord(c)<33 for c in value):
            links.append('<a href="'+e(value)+'" target="_blank" rel="noopener noreferrer">'+e(value)+'</a>')
        else:links.append(e(value))
    return '<br>'.join(links)


def evidence_lines(items):
    """Keep source conditions inspectable without printing JSON into a queue."""
    out=[]
    for item in items:
        item=str(item)
        if len(item)>120 or item.startswith('Matched source condition:'):
            label,separator,rest=item.partition(': ')
            if not separator:label,rest='Detailed evidence',item
            out.append('<details><summary>'+e(label)+'</summary><code class="block">'+e(rest)+'</code></details>')
        else:out.append('<p>'+e(item)+'</p>')
    return ''.join(out)


def evidence_url(event_ref,return_to='/network'):
    return '/evidence?'+urlencode({'event_ref':event_ref,'return_to':return_to})


def local_return(value):
    """Only return to supported local investigation views, never an external URL."""
    if not isinstance(value,str) or len(value)>4096 or '\\' in value or any(ord(c)<32 for c in value):return '/network'
    try:parsed=urlsplit(value)
    except ValueError:return '/network'
    if parsed.scheme or parsed.netloc or parsed.path not in {'/network','/triage','/attack-surface'}:return '/network'
    return value
