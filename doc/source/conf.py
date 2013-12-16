# -*- coding: utf-8 -*-
 
                                                            
                                                
 
                                                                                
 
                                                                     
                     
 
                                                                        
                            

import sys, os

                                                                               
                                                                             
                                                                               
                                         
sys.path.insert(0, os.path.abspath('../..'))


                                                                                

                                                                      
                     

                                                                                
                                                                
extensions = ['sphinx.ext.autodoc', 'sphinx.ext.intersphinx', 'sphinx.ext.ifconfig']

                                                                        
templates_path = ['_templates']

                                 
source_suffix = '.rst'

                               
#source_encoding = 'utf-8-sig'

                              
master_doc = 'index'

                                        
project = u'Faraday'
copyright = u'2010-2012, Infobyte Security Research'

                                                                              
                                                                           
                  
 
                        
version = '0.0.1'
                                                 
release = '0.0.1'

                                                                          
                                    
                

                                                                            
                                   
           
                                                            
                        

                                                                      
                                                      
exclude_patterns = []

                                                                                
                    

                                                                     
                                

                                                                       
                                      
                        

                                                                         
                                      
                     

                                                              
pygments_style = 'sphinx'

                                                      
                            


                                                                                

                                                                           
                           
html_theme = 'default'

                                                                             
                                                                   
                
                        

                                                                            
                     

                                                                     
                                       
                  

                                                                             
                        

                                                                            
                 
                 

                                                                             
                                                                            
               
                    

                                                                             
                                                                             
                                                                         
html_static_path = ['_static']

                                                                             
                                  
                                    

                                                                   
                                   
                            

                                                                  
                   

                                                                           
                 
                           

                                         
                           

                                  
                      

                                                                    
                         

                                                            
                            

                                                                               
                        

                                                                            
                           

                                                                            
                                                                             
                                                  
                         

                                                              
                        

                                              
htmlhelp_basename = 'Faradaydoc'


                                                                                

                                    
                            

                                           
                         

                                                             
                                                                                
latex_documents = [
  ('index', 'Faraday.tex', u'Faraday Documentation',
   u'Infobyte Security Research', 'manual'),
]

                                                                               
                 
                  

                                                                            
               
                        

                                                     
                            

                                                   
                        

                                          
                    

                                                    
                      

                                         
                            


                                                                                

                                           
                                                                  
man_pages = [
    ('index', 'faraday', u'Faraday Documentation',
     [u'Infobyte Security Research'], 1)
]


                                                                              
intersphinx_mapping = {'http://docs.python.org/': None}
